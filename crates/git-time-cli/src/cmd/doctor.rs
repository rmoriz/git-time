//! `git time doctor`: say what is wired, what is pinned, and what is wrong.
//!
//! One line per fact, on stdout, so the output can be read and grepped: where the
//! binary is, which hooks directory git uses, the state of every hook this tool
//! owns (`ours`, `chained`, `foreign`, `absent`, `not-executable`, `dangling`),
//! whether `time.gate` agrees with each installed `pre-*` hook, how many
//! authorities are configured, and each anchor's path, SHA-256 fingerprint,
//! first root's expiry and whether the pin was ever compared.
//!
//! These things make it exit `1`: no authority at all, an anchor that is missing,
//! unreadable or not a parseable certificate bundle, an anchor bundle with no
//! root valid now, an anchor pinned without a comparison (a `tofu` marker), a
//! HEAD block naming a root this machine has not pinned, a gate
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

/// Whether `id`'s pin carries the `tofu` marker.
///
/// Read the way the policy reads it — only a value that parses true marks — so
/// doctor and the seal warning cannot disagree about whether a row is quiet.
fn marker(repo: &Repo, id: &str) -> Result<bool, Exit> {
    crate::cmd::tsa::marked(repo, id)
}

/// The URL `id` should be refetched from.
///
/// A preset publishes its bundle where the table says (`anchor_url`), which is
/// not always the token endpoint: `actalis` answers a GET with 400 and leaves
/// the next POST at 503, and `cartaodecidadao` never serves its root there. An
/// id the table does not know can only be fetched from its configured URL.
fn fetch_url(repo: &Repo, id: &str) -> Result<Option<String>, Exit> {
    if let Some(preset) = git_time_core::presets::find(id) {
        return Ok(Some(preset.anchor_url.to_owned()));
    }
    repo.config_non_empty(&format!("time.tsa.{id}.url"))
        .map_err(Exit::config)
}

/// The command that re-fetches `id` from `url`, runnable as printed.
fn fetch_cmd(url: &str, id: &str) -> String {
    format!(
        "git time anchor fetch {url} --id {id}{}",
        if url.starts_with("http://") {
            " --insecure-http"
        } else {
            ""
        }
    )
}

/// The command that pins `fingerprint` for `id`, runnable as printed.
///
/// `restore` can only fetch a preset (the evidence does not carry a URL) and its
/// positional is a commit, so the accept is the only argument it takes. Any
/// other id is fetched from the URL [`fetch_url`] answers — the same one a fetch
/// reads, which the tests can stub — and an id the config has lost is configured
/// first.
fn remedy(repo: &Repo, id: &str, fingerprint: &str) -> String {
    let url = fetch_url(repo, id).ok().flatten();
    match (git_time_core::presets::find(id).is_some(), url) {
        // The positional of `restore` is a commit, so it must not be given.
        (true, Some(_)) => format!("git time tsa restore --accept {id}={fingerprint}"),
        (true, None) => format!("git time tsa preset add {id}"),
        (false, Some(url)) => format!("{} --accept {id}={fingerprint}", fetch_cmd(&url, id)),
        (false, None) => format!("git time tsa add <url> --id {id}"),
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
        // Resolve like every reader: an `anchor` key when there is one, the
        // default path otherwise. Only the resolved file decides "missing", so a
        // url-only section with a bundle is not called missing.
        let path = anchors::target(repo, id)?;
        match std::fs::read(&path) {
            Err(error) => {
                report.say(format!("anchor {id}: {} missing ({error})", path.display()));
                report.problem(format!(
                    "missing anchor for `{id}`: {} ({error})",
                    path.display()
                ));
                let tofu = marker(repo, id)?;
                if tofu {
                    // The bundle is gone, so `confirm` has nothing to check the
                    // value against yet: pin it again first.
                    let then = format!("git time anchor confirm {id}");
                    match fetch_url(repo, id)? {
                        Some(url) => report.problem(format!(
                            "`anchor {id}` is pinned but was never compared (pin it first: \
                             {}, then: {then})",
                            fetch_cmd(&url, id)
                        )),
                        None => report.problem(format!(
                            "`anchor {id}` is pinned but was never compared (configure it first: \
                             git time tsa add <url> --id {id}, then: {then})"
                        )),
                    }
                }
                anchor_reports.push(json!({
                    "id": id,
                    "path": path,
                    "fingerprint": Value::Null,
                    "missing": true,
                    "unparseable": false,
                    "roots": 0,
                    "expired": 0,
                    "tofu": tofu,
                }));
            }
            Ok(bytes) => {
                // The policy needs the key, not just a resolvable bundle: a
                // url-only section is refused as `Missing anchor` at seal and
                // verify, so one that holds a bundle is still a problem here.
                let anchored = repo
                    .config_non_empty(&format!("time.tsa.{id}.anchor"))
                    .map_err(Exit::config)?;
                let url = repo
                    .config_non_empty(&format!("time.tsa.{id}.url"))
                    .map_err(Exit::config)?;
                // A pin that had nothing to compare when it was made. It still
                // verifies, so it is a standing finding rather than a failure —
                // but nothing else in the repository ever disturbs it, so this
                // is where it has to stay visible.
                let tofu = marker(repo, id)?;
                // The same load the policy does, so a bundle that is only
                // PEM-shaped is a problem here rather than `Untrusted` at
                // the next commit.
                let parse = AnchorStore::load(&[(id.clone(), path.clone())]);
                let fingerprint = anchors::fingerprint(&bytes);
                // The first *root*'s date, never the first certificate: a
                // leaf-first bundle would otherwise date a leaf.
                let expiry = anchors::roots(&path)
                    .as_deref()
                    .and_then(|roots| roots.first())
                    .map(|root| format!(" {}", anchors::expiry_text(&root.not_after, now)))
                    .unwrap_or_default();
                report.say(format!(
                    "anchor {id}: {} sha256 {fingerprint}{expiry}",
                    path.display()
                ));
                if anchored.is_none() {
                    report.problem(format!(
                        "anchor {id}: no `time.tsa.{id}.anchor` configured, so the policy \
                         refuses it (run: git time tsa add {id} --anchor {})",
                        path.display()
                    ));
                }
                if url.is_none() {
                    report.problem(format!(
                        "anchor {id}: no `time.tsa.{id}.url` configured, so the policy \
                         refuses it (run: git time tsa add <url> --id {id})"
                    ));
                }
                if tofu {
                    // The root the confirmation is about: the first one, so the
                    // hint carries a value `confirm` accepts rather than the
                    // SHA-256 of the whole file.
                    let root = crate::cmd::anchor::root_certificates(&path)
                        .and_then(|roots| roots.into_iter().next());
                    match root {
                        Some(root) => {
                            let value = trust::fingerprint(&root);
                            report.say(format!("anchor {id}: tofu {value}"));
                            report.problem(format!(
                                "`anchor {id}` is pinned but was never compared (confirm it: \
                                 git time anchor confirm {id} {value})"
                            ));
                        }
                        None => report.problem(format!(
                            "`anchor {id}` is pinned but was never compared (confirm it: \
                             git time anchor confirm {id})"
                        )),
                    }
                }
                let mut roots = 0;
                let mut expired = 0;
                if let Err(ref error) = parse {
                    report.problem(format!(
                        "unparseable anchor for `{id}` at {}: {error}",
                        path.display()
                    ));
                } else if let Ok(store) = &parse
                    && let Some(entry) = store.anchor(id)
                {
                    let valid = entry.roots_at(now);
                    roots = entry.roots.len();
                    // `roots_at` filters both ends, so a root whose window
                    // has not opened yet is not valid — but it is not
                    // expired either. Only a `notAfter` that is past counts.
                    expired = entry
                        .roots
                        .iter()
                        .filter(|root| {
                            x509_cert::Certificate::from_der(root.as_bytes())
                                .ok()
                                .is_some_and(|certificate| {
                                    anchors::expired(&anchors::not_after(&certificate), now)
                                })
                        })
                        .count();
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
                            // The fingerprint is the root a fetch is meant
                            // to hand back (the newest one, as a listing
                            // shows it), spelled out so the line can be
                            // pasted. `restore`'s positional is a commit,
                            // so the accept is the only argument.
                            let newest = anchors::roots(&path)
                                .as_deref()
                                .and_then(|roots| crate::cmd::tsa::looming(roots, now))
                                .map(|root| root.fingerprint.clone());
                            report.problem(format!(
                                "`anchor {id}` has no root valid now (accept a fresh one: {})",
                                remedy(repo, id, newest.as_deref().unwrap_or("<fp>"))
                            ));
                        } else {
                            // Only a root that is valid now can be the one
                            // in use, so a future-dated root must not push
                            // the deadline past it.
                            let latest = valid
                                .iter()
                                .filter_map(|root| {
                                    x509_cert::Certificate::from_der(root.as_bytes()).ok()
                                })
                                .filter_map(|certificate| {
                                    i64::try_from(
                                        certificate
                                            .tbs_certificate()
                                            .validity()
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
                    "path": path,
                    "fingerprint": fingerprint,
                    "missing": false,
                    "unparseable": parse.is_err(),
                    "roots": roots,
                    "expired": expired,
                    "tofu": tofu,
                }));
            }
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
            "HEAD names `anchor {id}` fingerprint {fingerprint}, which is not pinned ({})",
            remedy(repo, &id, &fingerprint)
        ));
    }
    // An anchor for an id without a url is invisible to the policy; say so.
    for anchor in &configured {
        let url = repo
            .config_non_empty(&format!("time.tsa.{}.url", anchor.id))
            .map_err(Exit::config)?;
        if url.is_none() {
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
