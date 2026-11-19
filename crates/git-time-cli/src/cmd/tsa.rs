//! `git time tsa`: the registry of timestamp authorities.
//!
//! An authority is a `time.tsa.<id>` section of the **local** repository
//! config; `add` writes it, `list` reads it, `remove` deletes it whole. Nothing
//! here talks to the network — `preset add` is the one exception and goes
//! through the same fetch path `install` uses.
//!
//! A value is validated before the first key is written, so a refused `add`
//! leaves no half section behind. The policy OID is checked by
//! [`StampRequest::with_policy`], the same authority the request builder uses, so
//! a typo is rejected now instead of at the first seal.
//!
//! An id is derived from the URL host when `--id` is absent (`https://tsa.
//! example.net/tsr` becomes `tsa-example-net`) and is always restricted to
//! `[a-z0-9-]`: it ends up in a config key, a trailer value and a file name, so
//! anything else would need quoting somewhere.
//!
//! `select` is the cursor UI over the preset table: tick what this repository
//! should use, save, and only then are anchors pinned and unchosen preset
//! sections removed. It needs a terminal unless `--interactive` says an answer
//! is being piped; a script otherwise uses `preset add` or `add`.

use std::collections::BTreeSet;
use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::path::PathBuf;

use clap::Subcommand;
use git_time_core::imprint::{Alg, Digest};
use git_time_core::presets;
use git_time_core::repo::Repo;
use git_time_core::trust::AnchorStore;
use git_time_core::tsa::StampRequest;
use serde_json::{Value, json};

use crate::cmd::{Exit, anchors, git_stdout, install, open, picker};

/// The subcommands of `git time tsa`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Register a timestamp authority in the local repository config.
    Add {
        /// The endpoint the requests are posted to.
        url: String,
        /// The config id; derived from the URL host when absent.
        #[arg(long, value_name = "ID")]
        id: Option<String>,
        /// The PEM bundle pinned for this id.
        #[arg(long, value_name = "PATH")]
        anchor: Option<PathBuf>,
        /// The imprint algorithm.
        #[arg(long, value_enum, default_value = "sha256")]
        alg: AlgName,
        /// The TSA policy OID to request.
        #[arg(long, value_name = "OID")]
        policy: Option<String>,
        /// Per-attempt timeout.
        #[arg(long, value_name = "DURATION", default_value = "6s")]
        timeout: String,
        /// Accept a plain `http://` endpoint.
        #[arg(long)]
        insecure_http: bool,
    },
    /// List the configured authorities.
    List {
        /// Print the listing as one JSON array.
        #[arg(long)]
        json: bool,
    },
    /// Delete an authority's whole `time.tsa.<id>` section.
    Remove {
        /// The config id to delete.
        id: String,
    },
    /// Work with the built-in public authority presets.
    Preset {
        #[command(subcommand)]
        command: PresetCommand,
    },
    /// Choose interactively which preset authorities to enable here.
    Select {
        /// Prompt even when stdin is not a terminal, so an answer can be piped.
        #[arg(long)]
        interactive: bool,
        /// Print the selection and what would be written, change nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Pin the anchors a range's evidence names, so it can be verified here.
    Restore {
        /// A git rev-range. Defaults to every commit reachable from HEAD.
        #[arg(long, value_name = "RANGE")]
        range: Option<String>,
        /// Commits to read on top of any range.
        commits: Vec<String>,
    },
}

/// The subcommands of `git time tsa preset`.
#[derive(Debug, Subcommand)]
pub enum PresetCommand {
    /// Print the built-in presets.
    List,
    /// Configure one built-in preset, anchor included.
    Add {
        /// The preset name.
        name: String,
    },
}

/// An algorithm name as the command line spells it.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum AlgName {
    #[value(name = "sha256")]
    Sha256,
    #[value(name = "sha512")]
    Sha512,
}

impl AlgName {
    fn alg(self) -> Alg {
        match self {
            Self::Sha256 => Alg::Sha256,
            Self::Sha512 => Alg::Sha512,
        }
    }
}

/// Run one `git time tsa` subcommand.
pub async fn run(directory: Option<PathBuf>, command: Command) -> Exit {
    let repo = match open(directory) {
        Ok(repo) => repo,
        Err(exit) => return exit,
    };
    match command {
        Command::Add {
            url,
            id,
            anchor,
            alg,
            policy,
            timeout,
            insecure_http,
        } => add(
            &repo,
            NewTsa {
                url: &url,
                id: id.as_deref(),
                anchor,
                alg: alg.alg(),
                policy,
                timeout: &timeout,
                insecure_http,
            },
        ),
        Command::List { json } => list(&repo, json),
        Command::Remove { id } => remove(&repo, &id),
        Command::Preset { command } => match command {
            PresetCommand::List => preset_list(&repo),
            PresetCommand::Add { name } => preset_add(&repo, &name).await,
        },
        Command::Select {
            interactive,
            dry_run,
        } => select(&repo, interactive, dry_run).await,
        Command::Restore { range, commits } => restore(&repo, range.as_deref(), &commits).await,
    }
}

/// The fields `tsa add` was given.
struct NewTsa<'a> {
    url: &'a str,
    id: Option<&'a str>,
    anchor: Option<PathBuf>,
    alg: Alg,
    policy: Option<String>,
    timeout: &'a str,
    insecure_http: bool,
}

/// Write one `time.tsa.<id>` section, validating everything first.
fn add(repo: &Repo, new: NewTsa<'_>) -> Exit {
    let NewTsa {
        url,
        id,
        anchor,
        alg,
        policy,
        timeout,
        insecure_http,
    } = new;
    if let Err(exit) = validate_url("tsa", url, insecure_http) {
        return exit;
    }
    let id = match id.map(str::to_owned) {
        Some(id) => id,
        None => match derive_id(url) {
            Ok(id) => id,
            Err(exit) => return exit,
        },
    };
    if let Err(exit) = validate_id("tsa", &id) {
        return exit;
    }
    if let Err(exit) = validate_timeout(timeout) {
        return exit;
    }
    let policy = match policy {
        Some(policy) => match validate_policy(alg, &policy) {
            Ok(()) => Some(policy),
            Err(exit) => return exit,
        },
        None => None,
    };
    let base = format!("time.tsa.{id}");
    // The whole section is checked, not just its `url`: a section left without
    // a `url` by hand or by a half-written loop would otherwise be merged into,
    // keeping its stale `anchor`, `policy` or `timeout`.
    match anchors::section_exists(repo, &id) {
        Ok(true) => {
            return Exit::seal(format!(
                "git time tsa: `{id}` is already configured; edit its keys, or remove it first"
            ));
        }
        Ok(false) => {}
        Err(exit) => return exit,
    }

    let anchor = anchor.unwrap_or_else(|| anchors::dir().join(format!("{id}.pem")));
    // The path is recorded as given; only its resolution is created, so the
    // stored key stays readable and the parent can actually be written later.
    let resolved_anchor = anchors::resolve(repo, &anchor);
    if let Some(parent) = resolved_anchor.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return Exit::config(format!(
            "cannot create the anchor directory {}: {error}",
            parent.display()
        ));
    }
    let mut fields = vec![
        ("url", url.to_owned()),
        ("alg", alg.as_str().to_owned()),
        ("anchor", anchor.to_string_lossy().into_owned()),
        ("timeout", timeout.to_owned()),
    ];
    if let Some(policy) = policy {
        fields.push(("policy", policy));
    }
    if insecure_http && url.starts_with("http://") {
        fields.push(("insecure-http", "true".to_owned()));
    }
    for (field, value) in fields {
        if let Err(exit) = local_set(repo, &format!("{base}.{field}"), &value) {
            return exit;
        }
    }
    println!("tsa {id}: {url} (anchor {})", anchor.display());
    Exit::ok()
}

/// One line per configured authority, or the same fields as JSON.
fn list(repo: &Repo, json: bool) -> Exit {
    let ids = match anchors::tsa_ids(repo) {
        Ok(ids) => ids,
        Err(exit) => return exit,
    };
    let mut configured = match anchors::configured(repo) {
        Ok(configured) => configured,
        Err(exit) => return exit,
    };
    configured.sort_by(|left, right| left.id.cmp(&right.id));

    let mut rows = Vec::with_capacity(ids.len());
    for id in ids {
        let url = match local_get(repo, &format!("time.tsa.{id}.url")) {
            Ok(url) => url.unwrap_or_default(),
            Err(exit) => return exit,
        };
        let alg = match local_get(repo, &format!("time.tsa.{id}.alg")) {
            Ok(alg) => alg.unwrap_or_else(|| "sha256".to_owned()),
            Err(exit) => return exit,
        };
        let insecure_http = match local_get(repo, &format!("time.tsa.{id}.insecure-http")) {
            Ok(Some(value)) => reads_true(&value),
            Ok(None) => false,
            Err(exit) => return exit,
        };
        // The configured key wins, as it does in `Policy::load`; the default is
        // only what `add` would have written.
        let anchor = configured
            .iter()
            .find(|anchor| anchor.id == id)
            .map_or_else(
                || anchors::dir().join(format!("{id}.pem")),
                |anchor| anchor.path.clone(),
            );
        let anchored = pinned(&id, &anchor);
        let fingerprint =
            crate::cmd::anchor::first_certificate_at(&anchor).map(|der| anchors::fingerprint(&der));
        rows.push((id, url, alg, anchor, anchored, fingerprint, insecure_http));
    }

    if json {
        let rows: Vec<Value> = rows
            .iter()
            .map(
                |(id, url, alg, anchor, anchored, fingerprint, insecure_http)| {
                    json!({
                        "id": id,
                        "url": url,
                        "alg": alg,
                        "anchor": anchor.to_string_lossy(),
                        "anchored": anchored,
                        "fingerprint": fingerprint,
                        "insecure_http": insecure_http,
                    })
                },
            )
            .collect();
        match serde_json::to_string_pretty(&rows) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                return Exit::config(format!("cannot render JSON: {error}"));
            }
        }
    } else {
        for (id, url, alg, anchor, anchored, fingerprint, insecure_http) in &rows {
            println!(
                "{id} {url} {alg} {} {} ({}){}",
                anchor.display(),
                fingerprint.as_deref().unwrap_or("-"),
                if *anchored { "anchored" } else { "missing" },
                if *insecure_http { " insecure-http" } else { "" },
            );
        }
    }
    Exit::ok()
}

/// Delete an authority's whole section.
fn remove(repo: &Repo, id: &str) -> Exit {
    if let Err(exit) = validate_id("tsa", id) {
        return exit;
    }
    let key = format!("time.tsa.{id}.url");
    match local_get(repo, &key) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Exit::seal(format!("git time tsa: no TSA `{id}` is configured"));
        }
        Err(exit) => return exit,
    }
    if let Err(exit) = git_stdout(
        repo,
        &[
            "config",
            "--local",
            "--remove-section",
            &format!("time.tsa.{id}"),
        ],
    ) {
        return exit;
    }
    println!("tsa {id}: removed");
    Exit::ok()
}

/// Print the built-in presets and whether their anchor is pinned here.
fn preset_list(_repo: &Repo) -> Exit {
    for preset in &presets::PRESETS {
        let anchor = anchors::dir().join(format!("{}.pem", preset.name));
        println!(
            "{} {} {} {} {} ({})",
            preset.name,
            preset.url,
            preset.alg,
            // What `install` writes by default, and what is opt-in.
            if preset.curated { "default" } else { "opt-in" },
            // A pinned root is verifiable on the first fetch; the rest are
            // trust on first use and say so here as well as at the pin.
            preset.fingerprint.unwrap_or("tofu"),
            if pinned(preset.name, &anchor) {
                "anchored"
            } else {
                "missing"
            }
        );
    }
    Exit::ok()
}

/// Configure one preset through the install fetch path.
async fn preset_add(repo: &Repo, name: &str) -> Exit {
    let Some(preset) = presets::find(name) else {
        return Exit::usage(format!(
            "git time tsa preset: unknown preset `{name}`; known: {}",
            presets::names().collect::<Vec<_>>().join(", ")
        ));
    };
    match pin_preset(repo, preset).await {
        Ok(()) => Exit::ok(),
        // The lines already said what failed; a refused root and a missing
        // bundle both mean the pin did not do its job, which is the whole
        // point of `preset add`.
        Err(_reason) => Exit::seal(String::new()),
    }
}

/// Pin one preset, printing what `tsa preset add` prints.
///
/// `Ok` means the anchor is pinned. The error is the reason it is not, for a
/// caller — `tsa restore` — that carries on with the next id instead of
/// stopping at the first authority the network or a fingerprint refuses.
async fn pin_preset(repo: &Repo, preset: &'static presets::Preset) -> Result<(), String> {
    let pinned = install::pin(repo, preset)
        .await
        .map_err(|exit| exit.message())?;
    println!("tsa {}: {} configured", preset.name, preset.url);
    if pinned.kept > 0 {
        println!("tsa {}: {} existing key(s) kept", preset.name, pinned.kept);
    }
    let reason = if pinned.fingerprint_mismatch {
        // The line naming both values was already said while pinning.
        Some("the fetched root is not the published fingerprint".to_owned())
    } else if pinned.unusable {
        // What is pinned still works, but this fetch did not bring a bundle,
        // so the anchor is not the one that was just asked for.
        Some("the fetch brought no usable bundle; the pinned anchor is unchanged".to_owned())
    } else {
        pinned.missing_anchor.map(|path| {
            format!(
                "no anchor at {}; tokens of that authority cannot be verified until it is pinned",
                path.display()
            )
        })
    };
    match reason {
        Some(reason) => {
            eprintln!("rfc3161: warning: tsa {}: {reason}", preset.name);
            Err(reason)
        }
        None => Ok(()),
    }
}

/// Pin the anchors the evidence of `range`/`commits` names.
///
/// A clone has neither the `time.tsa.*` sections nor the pinned bundles — they
/// are per-machine on purpose — so `verify` reports every token `UNTRUSTED`
/// until they are backfilled. The ids are read straight from the blocks, which
/// is the one place that survives the config being gone; a preset carries a
/// published root, so the fetch is checked rather than trusted on first use.
/// An id that is not a preset cannot be fetched without its URL and is named
/// with the command that would configure it.
async fn restore(repo: &Repo, range: Option<&str>, commits: &[String]) -> Exit {
    let oids = match super::targets(repo, "tsa restore", range, commits) {
        Ok(oids) => oids,
        Err(exit) => return exit,
    };
    let configured = anchors::configured(repo).unwrap_or_default();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut todo: Vec<&'static presets::Preset> = Vec::new();
    let mut unknown: BTreeSet<String> = BTreeSet::new();
    let mut skips = 0_usize;
    for oid in &oids {
        let ids = match git_time_core::verify::named_tsas(repo, oid) {
            Ok(ids) => ids,
            Err(error) => return Exit::seal(format!("git time tsa restore: {oid}: {error}")),
        };
        for id in ids {
            if !seen.insert(id.clone()) {
                continue;
            }
            // Already pinned and loadable: nothing to do, and no fetch.
            let pinned_here = configured
                .iter()
                .find(|anchor| anchor.id == id)
                .is_some_and(|anchor| anchor.path.exists() && pinned(&id, &anchor.path));
            if pinned_here {
                skips += 1;
            } else if let Some(preset) = presets::find(&id) {
                todo.push(preset);
            } else {
                unknown.insert(id);
            }
        }
    }

    if seen.is_empty() {
        println!("tsa: the evidence names no authority");
        return Exit::ok();
    }
    if skips > 0 {
        println!("tsa: {skips} authority(ies) already pinned");
    }

    let mut restored = 0_usize;
    let mut refused: Vec<(&str, String)> = Vec::new();
    for preset in &todo {
        match pin_preset(repo, preset).await {
            Ok(()) => restored += 1,
            Err(reason) => refused.push((preset.name, reason)),
        }
    }
    // The warning for each refusal was already said by `pin_preset`; only the
    // count is left to say here.
    debug_assert!(refused.iter().all(|(_, reason)| !reason.is_empty()));
    // An id with no preset cannot be fetched: the evidence does not carry the
    // URL, so the fix is the two `add`-then-`fetch` steps by hand.
    for id in &unknown {
        eprintln!(
            "rfc3161: warning: tsa {id}: not a preset; configure it with `git time tsa add <url> \
             --id {id} --anchor <path>` and then `git time anchor fetch <url> --id {id}`"
        );
    }

    println!(
        "tsa: {restored} pinned, {} refused, {} without a preset, {skips} already pinned",
        refused.len(),
        unknown.len()
    );
    if restored > 0 {
        println!(
            "tsa: fingerprints were not reviewed; record and review them with `git time anchor pin`"
        );
    }
    if refused.is_empty() && unknown.is_empty() {
        Exit::ok()
    } else {
        // The point of the command is a repository that verifies, so an id the
        // evidence names and this machine still cannot check is a failure.
        Exit::seal(String::new())
    }
}

/// The question the selector asks, verbatim so the transcript is stable.
const SELECT_PROMPT: &str = "Authorities to enable (e.g. 1,3-4, all, none): ";

/// How many answers are taken before the selector gives up.
const SELECT_ATTEMPTS: usize = 3;

/// Run `git time tsa select`: show the table, take a selection, pin it.
///
/// The selection decides what is enabled *and* what is not: a preset section
/// that is not chosen is removed, so the command can narrow a configuration as
/// well as widen it. Sections whose id is not a preset are never touched.
pub(crate) async fn select(repo: &Repo, interactive: bool, dry_run: bool) -> Exit {
    let chosen = if std::io::stdin().is_terminal() {
        let mut selection = picker::Selection::default();
        if let Some(outcome) = picker::run(&mut selection, &presets::PRESETS) {
            match outcome {
                picker::Outcome::Save(chosen) => chosen,
                picker::Outcome::Abort => {
                    println!("nothing changed");
                    return Exit::ok();
                }
                picker::Outcome::Stay => Vec::new(),
            }
        } else {
            // A terminal, but no raw mode to be had: the line prompt still asks.
            match ask() {
                Ok(chosen) => chosen,
                Err(exit) => return exit,
            }
        }
    } else if interactive {
        // A piped answer: the line prompt reads it, one line.
        match ask() {
            Ok(chosen) => chosen,
            Err(exit) => return exit,
        }
    } else {
        // A prompt nobody answers hangs a script; say so instead.
        return Exit::usage(
            "git time tsa select: stdin is not a terminal; use `git time tsa preset add <id>`, \
             `git time tsa add <url>`, or `--interactive` with a piped answer",
        );
    };
    apply(repo, &chosen, dry_run).await
}

/// Print the preset table and take the selection, re-asking on nonsense.
fn ask() -> Result<Vec<usize>, Exit> {
    for (index, preset) in presets::PRESETS.iter().enumerate() {
        println!(
            "{}) {} {} {} {}{}",
            index + 1,
            preset.name,
            preset.url,
            if preset.curated { "default" } else { "opt-in" },
            match preset.fingerprint {
                Some(fingerprint) => format!("pinned {fingerprint}"),
                None => "tofu".to_owned(),
            },
            if preset.insecure_http {
                " insecure-http"
            } else {
                ""
            },
        );
    }

    for _ in 0..SELECT_ATTEMPTS {
        print!("{SELECT_PROMPT}");
        // The prompt has no newline, so it has to leave the buffer now.
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        match std::io::stdin().lock().read_line(&mut line) {
            // A terminal that closed is as good as an empty answer: nothing.
            Ok(0) => return Ok(Vec::new()),
            Ok(_) => {}
            Err(error) => {
                return Err(Exit::config(format!("cannot read the selection: {error}")));
            }
        }
        // A terminal echoes the answer and the newline; a pipe does not, so
        // without this the next output would start on the prompt line.
        if !std::io::stdin().is_terminal() {
            println!();
        }
        match parse_choice(&line, presets::PRESETS.len()) {
            Ok(chosen) => return Ok(chosen),
            Err(message) => eprintln!("git time tsa select: {message}"),
        }
    }
    Err(Exit::usage(format!(
        "git time tsa select: no valid selection after {SELECT_ATTEMPTS} attempts"
    )))
}

/// Turn `1,3-4`, `all`, `none` or an empty answer into zero-based indices.
///
/// The result keeps the order of the input and never repeats an index, so a
/// doubled `1,1` still enables one authority once.
pub(crate) fn parse_choice(input: &str, count: usize) -> Result<Vec<usize>, String> {
    let answer = input.trim().to_ascii_lowercase();
    if answer.is_empty() || answer == "none" {
        return Ok(Vec::new());
    }
    if answer == "all" {
        return Ok((0..count).collect());
    }
    let unrecognised = || format!("`{answer}` is not a selection; use 1,3-4, all or none");
    let mut chosen = Vec::new();
    for token in answer.split(',') {
        let token = token.trim();
        let (first, last) = match token.split_once('-') {
            Some((first, last)) => (first.trim(), last.trim()),
            None => (token, token),
        };
        let first = index(first, count).ok_or_else(unrecognised)?;
        let last = index(last, count).ok_or_else(unrecognised)?;
        if first > last {
            return Err(format!(
                "`{token}` counts backwards; write the smaller index first"
            ));
        }
        for index in first..=last {
            if !chosen.contains(&index) {
                chosen.push(index);
            }
        }
    }
    Ok(chosen)
}

/// A one-based number in the answer as a zero-based index, when it is in range.
fn index(text: &str, count: usize) -> Option<usize> {
    let value: usize = text.parse().ok()?;
    (1..=count).contains(&value).then(|| value - 1)
}

/// Disable what is not chosen, then pin what is.
async fn apply(repo: &Repo, chosen: &[usize], dry_run: bool) -> Exit {
    let configured = match anchors::configured(repo) {
        Ok(configured) => configured,
        Err(exit) => return exit,
    };
    // Only preset ids are managed here; a hand-added section stays.
    let unwanted: Vec<&str> = presets::names()
        .filter(|name| {
            !chosen
                .iter()
                .filter_map(|index| presets::PRESETS.get(*index))
                .any(|preset| preset.name == *name)
                && configured.iter().any(|anchor| anchor.id == *name)
        })
        .collect();

    if dry_run {
        for name in &unwanted {
            println!("would disable {name}");
        }
    } else {
        for name in &unwanted {
            if let Err(exit) = disable(repo, name) {
                return exit;
            }
        }
    }

    let mut failed = false;
    for index in chosen {
        let Some(preset) = presets::PRESETS.get(*index) else {
            continue;
        };
        if dry_run {
            println!(
                "would enable {} ({}) fingerprint {}",
                preset.name,
                preset.url,
                preset.fingerprint.unwrap_or("tofu")
            );
            continue;
        }
        match install::pin(repo, preset).await {
            Ok(pinned) => {
                if pinned.fingerprint_mismatch || pinned.missing_anchor.is_some() {
                    failed = true;
                    if let Some(path) = &pinned.missing_anchor {
                        if install::gate(repo).unwrap_or(false) {
                            eprintln!(
                                "rfc3161: warning: no anchor for `{}` at {}; with time.gate = \
                                 pre-commit every commit will be refused until it is pinned",
                                preset.name,
                                path.display()
                            );
                        }
                        println!("failed {}: no anchor could be pinned", preset.name);
                    } else {
                        println!(
                            "failed {}: the published root fingerprint did not match",
                            preset.name
                        );
                    }
                    continue;
                }
                let anchor = anchors::configured(repo)
                    .unwrap_or_default()
                    .into_iter()
                    .find(|anchor| anchor.id == preset.name)
                    .map(|anchor| anchor.path)
                    .unwrap_or_else(|| anchors::dir().join(format!("{}.pem", preset.name)));
                // The spelling the preset is written in: SHA-256 where it pins
                // one, SHA-1 for a SHA-1 pin and for trust on first use.
                let fingerprint = crate::cmd::anchor::first_certificate_at(&anchor)
                    .map(|der| install::digest_for(preset.fingerprint, &der))
                    .unwrap_or_default();
                println!(
                    "enabled {} ({}) fingerprint {fingerprint}",
                    preset.name, preset.url
                );
                if pinned.kept > 0 {
                    println!(
                        "enabled {} ({}): {} existing key(s) kept",
                        preset.name, preset.url, pinned.kept
                    );
                }
            }
            Err(exit) => return exit,
        }
    }
    if failed {
        if install::gate(repo).unwrap_or(false) {
            eprintln!(
                "rfc3161: warning: with time.gate = pre-commit every commit will be refused until \
                 the failed anchor(s) are pinned"
            );
        }
        Exit::seal(String::new())
    } else {
        Exit::ok()
    }
}

/// Delete one preset's whole section, saying so.
fn disable(repo: &Repo, id: &str) -> Result<(), Exit> {
    git_stdout(
        repo,
        &[
            "config",
            "--local",
            "--remove-section",
            &format!("time.tsa.{id}"),
        ],
    )?;
    println!("disabled {id}");
    Ok(())
}

/// Whether `id`'s anchor at `path` loads.
pub(crate) fn pinned(id: &str, path: &std::path::Path) -> bool {
    AnchorStore::load(&[(id.to_owned(), path.to_path_buf())]).is_ok()
}

/// Refuse a URL that is not `https`, unless plain `http` is accepted explicitly.
///
/// Shared with `anchor fetch`, so a bundle URL cannot slip in over plain http
/// where a TSA endpoint would be refused. `command` names the caller.
pub(crate) fn validate_url(command: &str, url: &str, insecure_http: bool) -> Result<(), Exit> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if url.starts_with("http://") {
        if insecure_http {
            eprintln!(
                "rfc3161: warning: `{url}` is plain http; a network attacker can swap the bundle"
            );
            return Ok(());
        }
        return Err(Exit::usage(format!(
            "git time {command}: `{url}` is plain http; pass --insecure-http to accept it"
        )));
    }
    Err(Exit::usage(format!(
        "git time {command}: `{url}` is not an https:// URL"
    )))
}

/// The id derived from `url`'s host: lowercase, every run of other characters a
/// single `-`.
fn derive_id(url: &str) -> Result<String, Exit> {
    let host = host_of(url)
        .ok_or_else(|| Exit::usage(format!("git time tsa: cannot read a host from `{url}`")))?;
    let mut slug = String::with_capacity(host.len());
    let mut dash = false;
    for character in host.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
            dash = false;
        } else if !dash && !slug.is_empty() {
            slug.push('-');
            dash = true;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        return Err(Exit::usage(format!(
            "git time tsa: cannot derive an id from `{url}`; pass --id"
        )));
    }
    Ok(slug)
}

/// The host of `url`, without userinfo or port.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if let Some(rest) = host.strip_prefix('[') {
        return Some(rest.split_once(']')?.0.to_owned());
    }
    Some(host.split(':').next()?.to_owned()).filter(|host| !host.is_empty())
}

/// Restrict an id to `[a-z0-9-]`; `command` names the caller in the message.
pub(crate) fn validate_id(command: &str, id: &str) -> Result<(), Exit> {
    if !id.is_empty()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Ok(());
    }
    Err(Exit::usage(format!(
        "git time {command}: id `{id}` may only hold a-z, 0-9 and `-`"
    )))
}

/// Accept the durations `Policy::load` accepts, so a typo is caught here.
fn validate_timeout(value: &str) -> Result<(), Exit> {
    let digits = value
        .strip_suffix("ms")
        .or_else(|| value.strip_suffix('s'))
        .or_else(|| value.strip_suffix('m'))
        .unwrap_or(value);
    let valid = !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && digits.parse::<u64>().is_ok();
    if valid {
        Ok(())
    } else {
        Err(Exit::usage(format!(
            "git time tsa: `{value}` is not a duration such as `10s`, `500ms` or bare seconds"
        )))
    }
}

/// Validate a policy through the request builder, whose wording a reader knows.
fn validate_policy(alg: Alg, policy: &str) -> Result<(), Exit> {
    let digest = Digest {
        alg,
        bytes: vec![0; alg.digest_len()],
    };
    StampRequest::new(digest, &mut rand::rng())
        .and_then(|request| request.with_policy(Some(policy.to_owned())))
        .map_err(|error| Exit::usage(format!("git time tsa: {error}")))?;
    Ok(())
}

/// Whether a config value is one of the git spellings of true.
fn reads_true(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "true" | "yes" | "on" | "1"
    )
}

/// One local config value, `None` when the key is unset.
fn local_get(repo: &Repo, key: &str) -> Result<Option<String>, Exit> {
    match git_stdout(repo, &["config", "--local", "--get", key]) {
        Ok(value) if !value.trim().is_empty() => Ok(Some(value.trim().to_owned())),
        Ok(_) => Ok(None),
        // git exits 1 for an unset key, which `git_stdout` reports as usage.
        Err(exit) if exit.code() == 2 => Ok(None),
        Err(exit) => Err(exit),
    }
}

/// Write one local config key.
fn local_set(repo: &Repo, key: &str, value: &str) -> Result<(), Exit> {
    git_stdout(repo, &["config", "--local", key, value]).map(|_| ())
}
