//! `git time tsa`: the registry of timestamp authorities.
//!
//! An authority is a `time.tsa.<id>` section of the **local** repository
//! config; `add` writes it, `list` reads it, `remove` deletes it whole. Nothing
//! here talks to the network unless it is asked to — `preset add` and
//! `preset list --refresh` go through the same fetch path `install` uses.
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
//! `select` is the cursor UI over the preset table: the configured authorities
//! start ticked, tick what this repository should use, save, and only then are
//! anchors pinned and preset sections missing from the answer removed. It needs
//! a terminal unless `--interactive` says an answer is being piped; a script
//! otherwise uses `preset add` or `add`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use clap::Subcommand;
use der::Decode as _;
use git_time_core::imprint::{Alg, Digest};
use git_time_core::presets;
use git_time_core::repo::Repo;
use git_time_core::trust::AnchorStore;
use git_time_core::tsa::StampRequest;
use serde_json::{Value, json};

use crate::cmd::{Exit, anchors, git_stdout, install, open, picker, probe};

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
        /// Accept a root the block does not name, as `<id>=<fingerprint>`.
        #[arg(long, value_name = "ID=FINGERPRINT")]
        accept: Vec<String>,
        /// Commits to read on top of any range.
        commits: Vec<String>,
    },
}

/// The subcommands of `git time tsa preset`.
#[derive(Debug, Subcommand)]
pub enum PresetCommand {
    /// Print the built-in presets.
    List {
        /// Ask every authority again and rewrite the cache before printing.
        #[arg(long)]
        refresh: bool,
    },
    /// Configure one built-in preset, anchor included.
    Add {
        /// The preset name.
        name: String,
        /// Accept a root that is not the published one, as `<id>=<fingerprint>`.
        #[arg(long, value_name = "ID=FINGERPRINT")]
        accept: Vec<String>,
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
    // A prompt nobody answers hangs a script, and that holds outside a
    // repository too: say so before anything is opened or read.
    if matches!(
        command,
        Command::Select {
            interactive: false,
            ..
        }
    ) && !std::io::stdin().is_terminal()
    {
        return needs_a_terminal();
    }
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
            PresetCommand::List { refresh } => preset_list(&repo, refresh).await,
            PresetCommand::Add { name, accept } => preset_add(&repo, &name, &accept).await,
        },
        Command::Select {
            interactive,
            dry_run,
        } => select(&repo, &[], "git time tsa select", interactive, dry_run).await,
        Command::Restore {
            range,
            accept,
            commits,
        } => restore(&repo, range.as_deref(), &accept, &commits).await,
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

/// One authority as `tsa list` shows it.
struct Row {
    id: String,
    url: String,
    alg: String,
    anchor: PathBuf,
    anchored: bool,
    /// The fingerprint of the newest root still valid, when the bundle loads:
    /// the one the authority line speaks about, as `tsa preset list` chooses it.
    fingerprint: Option<String>,
    insecure_http: bool,
    /// Every root of the bundle, in file order.
    roots: Option<Vec<anchors::RootRow>>,
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

    // One instant for the whole listing: every date is judged as of one moment.
    let now = jiff::Timestamp::now();
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
        let roots = anchors::roots(&anchor);
        // The authority line speaks about the newest root still valid, the same
        // choice `tsa preset list` makes: fingerprint and date describe the same
        // certificate, and neither depends on where append order put it.
        let fingerprint = roots
            .as_deref()
            .and_then(|roots| looming(roots, now))
            .map(|root| root.fingerprint.clone());
        rows.push(Row {
            id,
            url,
            alg,
            anchor,
            anchored,
            fingerprint,
            insecure_http,
            roots,
        });
    }

    if json {
        let rows: Vec<Value> = rows
            .iter()
            .map(|row| {
                // The authority line speaks about the newest live root, as the
                // text listing does; every root then gets a line of its own.
                let first = row.roots.as_deref().and_then(|roots| looming(roots, now));
                let roots: Vec<Value> = row
                    .roots
                    .iter()
                    .flatten()
                    .map(|root| {
                        json!({
                            "fingerprint": root.fingerprint,
                            "not_after": root.not_after,
                            "expired": anchors::expired(&root.not_after, now),
                        })
                    })
                    .collect();
                json!({
                    "id": row.id,
                    "url": row.url,
                    "alg": row.alg,
                    "anchor": row.anchor.to_string_lossy(),
                    "anchored": row.anchored,
                    "fingerprint": row.fingerprint,
                    "not_after": first.map(|root| root.not_after.as_str()),
                    "insecure_http": row.insecure_http,
                    "roots": roots,
                })
            })
            .collect();
        match serde_json::to_string_pretty(&rows) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                return Exit::config(format!("cannot render JSON: {error}"));
            }
        }
    } else {
        for row in &rows {
            let first = row.roots.as_deref().and_then(|roots| looming(roots, now));
            let not_after = first.map_or("-", |root| root.not_after.as_str());
            println!(
                "{} {} {} {} {} {} ({}){}",
                row.id,
                row.url,
                row.alg,
                row.anchor.display(),
                row.fingerprint.as_deref().unwrap_or("-"),
                anchors::expiry_text(not_after, now),
                if row.anchored { "anchored" } else { "missing" },
                if row.insecure_http {
                    " insecure-http"
                } else {
                    ""
                },
            );
            for root in row.roots.iter().flatten() {
                println!(
                    "  root {} {}",
                    root.fingerprint,
                    anchors::expiry_text(&root.not_after, now),
                );
            }
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

/// What the listing says about a row whose bundle is `roots`, with `cell` the
/// probe's answer for it.
///
/// A local certificate is the date a seal is checked against, so it comes first
/// and is printed as it is. Every root of a dead bundle reads `EXPIRED`, so a
/// dead pin cannot fall through to the probe cell; otherwise the date is the
/// newest live root's, since a bundle's order is append order and not date
/// order. Without one the cell speaks in the picker's words: a served root
/// reads `fetch <date>` (or the near-expiry and expired forms), a pending row
/// `…`, and a failed or unpublished reply `?`.
///
/// Nothing was asked (`Cell::Idle`) has no probe date: a row no table knows is
/// hand-added and reads `tofu`, the picker's word, because it publishes nothing
/// to pin; `not pinned` is the message for a built-in preset that publishes no
/// root either, so the missing date reads as the preset's shape and not as a
/// broken pin. A published built-in with no local certificate only says the
/// date is missing, `-`. No built-in row publishes nothing any more, so that
/// branch keeps a unit test instead of a row.
///
/// A served date carries no certificate of its own, so `now` judges it against
/// the caller's instant rather than a second clock read.
///
/// `rotated` appends ` !` to the state: the served root is one no root of the
/// local bundle holds, which is the rotation signal the picker also draws. It is
/// never set without a bundle, so an unpinned row keeps its plain wording.
pub(crate) fn pin_state(
    preset: &presets::Preset,
    roots: Option<&[anchors::RootRow]>,
    cell: picker::Cell,
    rotated: bool,
    now: jiff::Timestamp,
) -> String {
    let state = match roots.filter(|roots| !roots.is_empty()) {
        Some(roots) => {
            if roots
                .iter()
                .all(|root| anchors::expired(&root.not_after, now))
            {
                "EXPIRED".to_owned()
            } else {
                // The all-expired branch above took the no-live-root case, and
                // `looming` falls back to the newest root when none is live, so
                // a non-empty bundle always names a root here.
                let root = looming(roots, now).expect("a non-empty bundle names a root");
                anchors::expiry_text(&root.not_after, now)
            }
        }
        None => match cell {
            picker::Cell::Known(cached) => picker::served(&cached, now),
            picker::Cell::Pending => "…".to_owned(),
            picker::Cell::Unpublished | picker::Cell::Failed => "?".to_owned(),
            picker::Cell::Idle => {
                if presets::find(preset.name).is_none() {
                    "tofu".to_owned()
                } else if preset.fingerprints.is_empty() {
                    "not pinned".to_owned()
                } else {
                    "-".to_owned()
                }
            }
        },
    };
    if rotated {
        return format!("{state} !");
    }
    state
}

/// Whether `cell` serves a root no root of `roots` matches.
///
/// Only a non-empty bundle can judge anything, so without one there is no `!`.
/// When the cell holds no served root — failed, still waiting, never asked, or a
/// reply that named no published root — the last cached answer is what the row
/// would show next run, and the marker is read from it: a refresh that fails
/// must not blink a known rotation off.
///
/// The comparison is on the bare `anchors::fingerprint` spelling both sides
/// carry, exactly as the picker's `trust` column does it.
fn rotated(
    preset: &presets::Preset,
    roots: Option<&[anchors::RootRow]>,
    cell: picker::Cell,
    now: jiff::Timestamp,
) -> bool {
    let Some(roots) = roots.filter(|roots| !roots.is_empty()) else {
        return false;
    };
    let cached = match cell {
        picker::Cell::Known(cached) => Some(cached),
        _ => probe::cached(preset.name, now),
    };
    match cached {
        Some(cached) => !roots
            .iter()
            .any(|root| root.fingerprint == cached.fingerprint),
        None => false,
    }
}

/// Print the rows — the built-in table and every configured section — and
/// whether their anchor is pinned here.
///
/// The date comes from the local bundle where there is one, newest live root
/// first: for a preset that publishes no fingerprint that bundle is the only
/// place the date exists at all. Otherwise the probe cache is read — it is what
/// a plain run shows, and nothing is fetched for it, so the table stays offline.
/// A custom row says `custom` in the scope column instead of a tier it does not
/// have. `--refresh` is the one path that opens sockets: it re-queues every
/// authority through the picker's worker and waits for the queue to drain before
/// printing, because this is the surface a timer or a CI job reads. No entry is
/// dropped first, so a failed fetch leaves the previous date in place until its
/// TTL ages it out, and the ` !` a rotation put on the row is read from that
/// entry while the cell shows `?`. The cache is the only write either way; a
/// probe pins nothing.
async fn preset_list(repo: &Repo, refresh: bool) -> Exit {
    let rows = match rows(repo) {
        Ok(rows) => rows,
        Err(exit) => return exit,
    };
    // One instant for the local dates and the served ones, so every pinned row
    // is judged as of one moment and a row cannot straddle an expiry between
    // its date and its marker.
    let now = jiff::Timestamp::now();
    let (mut probes, missing) = picker::seed(rows, now);
    // A plain run asks nothing, so its queue is empty and the loop below exits
    // at once; a row the cache cannot answer keeps today's `-` rather than a `…`
    // that would never clear.
    let queue: Vec<usize> = if refresh {
        let published: Vec<usize> = rows
            .iter()
            .enumerate()
            .filter(|(_, preset)| !preset.fingerprints.is_empty())
            .map(|(index, _)| index)
            .collect();
        for index in &published {
            probes.set(*index, picker::Cell::Pending);
        }
        published
    } else {
        for index in &missing {
            probes.set(*index, picker::Cell::Idle);
        }
        Vec::new()
    };
    let skip = picker::skip_of(&queue, rows.len());
    let prober = probe::Prober::start(rows, probe::network_fetch(), &skip);
    // Blocks until the whole queue drains: this is the headless surface, so a
    // caller wants the finished answer. Only the network path bounds a dead
    // authority on its own (its fetch timeout); a stub runs through
    // `Command::output()` and can park. Drain before the check, so the last
    // replies are already in the table when `pending` reaches zero, then once
    // more after the loop: a reply sent between that drain and the check would
    // otherwise be left unread and print `…`.
    loop {
        let _ = picker::absorb(&prober, &mut probes);
        if prober.pending() == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = picker::absorb(&prober, &mut probes);
    for (index, preset) in rows.iter().enumerate() {
        // The configured bundle path when the repository named one, else the
        // default `install` writes.
        let anchor = anchors::bundle_path(preset);
        // Only a local certificate can say when it expires. Bundle order is not
        // date order after an append, so the newest root that is still valid is
        // the one shown.
        let roots = anchors::roots(&anchor);
        let state = pin_state(
            preset,
            roots.as_deref(),
            probes.cell(index),
            rotated(preset, roots.as_deref(), probes.cell(index), now),
            now,
        );
        println!(
            "{} {} {} {} {} {} ({})",
            preset.name,
            preset.url,
            preset.alg,
            // A custom row has no published tier; the rest are the default and
            // the opt-in set.
            if presets::find(preset.name).is_none() {
                "custom"
            } else if preset.curated {
                "default"
            } else {
                "opt-in"
            },
            // A pinned root is verifiable on the first fetch; the rest are
            // trust on first use and say so here as well as at the pin. After a
            // rotation the newest value is the one shown, not the list.
            preset.fingerprints.last().copied().unwrap_or("tofu"),
            state,
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
async fn preset_add(repo: &Repo, name: &str, accept: &[String]) -> Exit {
    let Some(preset) = presets::find(name) else {
        return Exit::usage(format!(
            "git time tsa preset: unknown preset `{name}`; known: {}",
            presets::names().collect::<Vec<_>>().join(", ")
        ));
    };
    // One preset names one id, so a bare fingerprint is unambiguous here.
    let accept = match crate::cmd::accept::one_or_id(accept, &[preset.name]) {
        Ok(accept) => accept,
        Err(error) => return Exit::usage(format!("git time tsa preset: {error}")),
    };
    match pin_preset(
        repo,
        preset,
        &accept,
        &BTreeMap::new(),
        &format!("git time tsa preset add {}", preset.name),
    )
    .await
    {
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
async fn pin_preset(
    repo: &Repo,
    preset: &'static presets::Preset,
    accept: &BTreeMap<String, String>,
    named: &BTreeMap<String, Vec<String>>,
    command: &str,
) -> Result<(), String> {
    let pinned = install::pin(repo, preset, accept, named, command)
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
///
/// A block also names the roots its tokens were verified with. A fetched root
/// that is one of them needs no asking; a root the blocks do not name is a
/// rotation and is appended only when `--accept <id>=<fingerprint>` names it.
/// Both values are printed either way, next to the signature state of each commit
/// that named the id, so a reader sees which blocks were unverified when they
/// chose.
///
/// An id that is not a preset cannot be fetched without its URL and is named
/// with the command that would configure it.
async fn restore(repo: &Repo, range: Option<&str>, accept: &[String], commits: &[String]) -> Exit {
    let oids = match super::targets(repo, "tsa restore", range, commits) {
        Ok(oids) => oids,
        Err(exit) => return exit,
    };
    let configured = anchors::configured(repo).unwrap_or_default();

    // Per id the roots the blocks name for it, and per commit its signature
    // state. Reading the evidence is what runs `sigcheck`, so the state is not
    // a second pass.
    let mut named: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut signed: Vec<(String, &'static str)> = Vec::new();
    for oid in &oids {
        let ids = match git_time_core::verify::named_tsas(repo, oid) {
            Ok(ids) => ids,
            Err(error) => return Exit::seal(format!("git time tsa restore: {oid}: {error}")),
        };
        if ids.is_empty() {
            continue;
        }
        let evidence = match git_time_core::verify::commit(
            repo,
            &AnchorStore::default(),
            oid,
            &git_time_core::policy::Policy::default(),
        ) {
            Ok(evidence) => evidence,
            Err(error) => return Exit::seal(format!("git time tsa restore: {oid}: {error}")),
        };
        for id in ids {
            let wanted = named.entry(id.clone()).or_default();
            for record in evidence.per_tsa.iter().filter(|record| record.id == id) {
                for root in &record.anchors {
                    if !wanted.contains(root) {
                        wanted.push(root.clone());
                    }
                }
            }
        }
        signed.push((oid.clone(), evidence.signature.as_str()));
    }

    if named.is_empty() {
        println!("tsa: the evidence names no authority");
        return Exit::ok();
    }

    // Nothing is fetched for an authority whose pinned bundle already holds a
    // root the blocks name (or when they name none at all): that evidence
    // verifies as it is.
    let mut todo: Vec<&'static presets::Preset> = Vec::new();
    let mut unknown: BTreeSet<String> = BTreeSet::new();
    let mut skips = 0_usize;
    for id in named.keys() {
        let path = configured
            .iter()
            .find(|anchor| anchor.id == *id)
            .map_or_else(
                || anchors::dir().join(format!("{id}.pem")),
                |anchor| anchor.path.clone(),
            );
        let wanted = named.get(id).map(Vec::as_slice).unwrap_or_default();
        if covers(id, &path, wanted) {
            skips += 1;
        } else if let Some(preset) = presets::find(id) {
            todo.push(preset);
        } else {
            unknown.insert(id.clone());
        }
    }

    // The ids in play are everything the history names, so a bare accept that
    // meets two of them is refused with both named.
    let in_play: Vec<&str> = named.keys().map(String::as_str).collect();
    let accept = match crate::cmd::accept::one_or_id(accept, &in_play) {
        Ok(accept) => accept,
        Err(error) => return Exit::usage(format!("git time tsa restore: {error}")),
    };

    if skips > 0 {
        println!("tsa: {skips} authority(ies) already pinned");
    }
    // The state sits next to each commit before the fetch: it is what a reader
    // weighs when they are asked to accept a root. A bad signature does not
    // block the pin — an unsigned clone is exactly the case restore is for.
    for (oid, signature) in &signed {
        println!("tsa: {} signature {signature}", super::short(oid));
    }

    let mut restored = 0_usize;
    let mut refused: Vec<(&str, String)> = Vec::new();
    for preset in &todo {
        match pin_preset(repo, preset, &accept, &named, "git time tsa restore").await {
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

/// The refusal for a `tsa select` nobody can answer.
fn needs_a_terminal() -> Exit {
    Exit::usage(
        "git time tsa select: stdin is not a terminal; use `git time tsa preset add <id>`, \
         `git time tsa add <url>`, or `--interactive` with a piped answer",
    )
}

/// Run `git time tsa select`: show the table, take a selection, pin it.
///
/// The selection decides what is enabled *and* what is not: a preset section
/// that is not chosen is removed, so the command can narrow a configuration as
/// well as widen it. Sections whose id is not a preset are never touched.
///
/// It starts from what is configured, so an authority left out of the answer
/// was unticked on purpose rather than forgotten by the start state.
///
/// `interactive` is not read here: the non-terminal refusal lives in [`run`], so
/// it fires before the repository is opened, and `install` only ever calls this
/// where an answer is expected.
///
/// `accept` is forwarded from `install`, whose own `--accept` would otherwise be
/// dropped by the handover: the ids it can name are the chosen ones, because
/// those are the only ids this run fetches.
pub(crate) async fn select(
    repo: &Repo,
    accept: &[String],
    command: &str,
    _interactive: bool,
    dry_run: bool,
) -> Exit {
    // The answer is the whole set: every preset section missing from it is
    // removed. An empty start would therefore drop every authority the user did
    // not mean to touch, and neither surface would show what is configured. The
    // ticks begin at the configuration; the answer stays authoritative over it.
    let seed = match already_enabled(repo) {
        Ok(seed) => seed,
        Err(exit) => return exit,
    };
    let chosen = if std::io::stdin().is_terminal() {
        let mut selection = initial(&seed);
        // Nothing asked yet, so the line-prompt fallback keeps `pin -` and the
        // picker path replaces this table with the cache seed once it owns the
        // terminal.
        let mut probes = picker::Probes::idle(presets::PRESETS.len());
        if let Some(outcome) = picker::run(&mut selection, &presets::PRESETS, &mut probes) {
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
            match ask(&seed, command) {
                Ok(chosen) => chosen,
                Err(exit) => return exit,
            }
        }
    } else {
        // A piped answer: the line prompt reads it, one line.
        match ask(&seed, command) {
            Ok(chosen) => chosen,
            Err(exit) => return exit,
        }
    };
    let accept = match accepted(accept, &chosen, command) {
        Ok(accept) => accept,
        Err(exit) => return exit,
    };
    apply(repo, &chosen, &accept, dry_run).await
}

/// Resolve `--accept` values for a selection against the rows it chose.
///
/// A bare fingerprint is unambiguous only when one row was chosen, so the ids in
/// play are the chosen ones and nothing else.
fn accepted(
    accept: &[String],
    chosen: &[usize],
    command: &str,
) -> Result<std::collections::BTreeMap<String, String>, Exit> {
    let ids: Vec<&str> = chosen
        .iter()
        .filter_map(|index| presets::PRESETS.get(*index))
        .map(|preset| preset.name)
        .collect();
    crate::cmd::accept::one_or_id(accept, &ids)
        .map_err(|error| Exit::usage(format!("{command}: {error}")))
}

/// One `time.tsa.<id>` section, as [`rows`] reads it.
///
/// An empty value counts as unset, as `local_get` reads a blanked key: a
/// `url=` neither makes a row nor erases the preset's own url.
#[derive(Default)]
struct Section {
    url: Option<String>,
    anchor: Option<String>,
    alg: Option<String>,
    policy: Option<String>,
    /// The `insecure-http` key, when set: the section wins over the preset's
    /// own value, exactly as `Policy::load` reads it.
    insecure_http: Option<bool>,
}

/// `text` leaked for the rest of the process.
fn leak_text(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

/// `path` resolved against `repo` and leaked for the rest of the process.
fn leak_path(repo: &Repo, path: &str) -> &'static Path {
    Box::leak(anchors::resolve(repo, Path::new(path)).into_boxed_path())
}

/// The rows a surface shows: the built-in table, then every section a path in.
///
/// A configured id the table knows overrides its row from the section — the
/// section is what seals, so the row must name what it points at, and a mirror
/// still serves the published roots the `!` marker is judged against. An unknown
/// id needs a url to be enableable at all, so a url-less section is no row and
/// is left alone by `apply`. Strings are leaked: the process is about to exit,
/// and every `&'static [Preset]` signature then stands unchanged.
pub(crate) fn rows(repo: &Repo) -> Result<&'static [presets::Preset], Exit> {
    let mut sections: BTreeMap<String, Section> = BTreeMap::new();
    for (key, value) in anchors::listing(repo)? {
        let Some(rest) = key.strip_prefix("time.tsa.") else {
            continue;
        };
        let Some((id, field)) = rest.rsplit_once('.') else {
            continue;
        };
        let section = sections.entry(id.to_owned()).or_default();
        let slot = match field {
            "url" if !value.is_empty() => &mut section.url,
            "anchor" if !value.is_empty() => &mut section.anchor,
            "alg" if !value.is_empty() => &mut section.alg,
            "policy" if !value.is_empty() => &mut section.policy,
            "insecure-http" if !value.is_empty() => {
                section.insecure_http = Some(reads_true(&value));
                continue;
            }
            _ => continue,
        };
        *slot = Some(value);
    }

    let mut rows = presets::PRESETS.to_vec();
    for id in anchors::tsa_ids(repo)? {
        let Some(section) = sections.get(&id) else {
            continue;
        };
        if let Some(index) = presets::PRESETS.iter().position(|preset| preset.name == id) {
            if let Some(url) = &section.url {
                rows[index].url = leak_text(url.clone());
            }
            if let Some(alg) = &section.alg {
                rows[index].alg = leak_text(alg.clone());
            }
            if let Some(policy) = &section.policy {
                rows[index].policy = Some(leak_text(policy.clone()));
            }
            // The configured key wins, as it does in `Policy::load`; an unset
            // key leaves the preset's own transport alone.
            if let Some(insecure_http) = section.insecure_http {
                rows[index].insecure_http = insecure_http;
            }
            if let Some(anchor) = &section.anchor {
                rows[index].anchor_path = Some(leak_path(repo, anchor));
            }
            continue;
        }
        let Some(url) = &section.url else {
            continue;
        };
        rows.push(presets::Preset {
            name: leak_text(id),
            url: leak_text(url.clone()),
            anchor_url: "",
            chain: &[],
            alg: leak_text(section.alg.clone().unwrap_or_else(|| "sha256".to_owned())),
            policy: section
                .policy
                .as_ref()
                .map(|policy| leak_text(policy.clone())),
            fingerprints: &[],
            insecure_http: section.insecure_http.unwrap_or(false),
            anchor_path: section
                .anchor
                .as_ref()
                .map(|anchor| leak_path(repo, anchor)),
            curated: false,
        });
    }
    Ok(Box::leak(rows.into_boxed_slice()))
}

/// The preset indices the configuration already enables, for the seed.
///
/// A hand-added section has a row now, but the seeding is still preset-only: it
/// matches table ids, and a later task widens it to every configured row. The
/// result is in table order, like the picker's own state, so a piped answer
/// enables in the order shown.
fn already_enabled(repo: &Repo) -> Result<Vec<usize>, Exit> {
    let ids = anchors::tsa_ids(repo)?;
    let mut seed: Vec<usize> = ids
        .iter()
        .filter_map(|id| presets::PRESETS.iter().position(|preset| preset.name == id))
        .collect();
    seed.sort_unstable();
    Ok(seed)
}

/// The picker's opening state.
///
/// A separate call so the seed reaches the cursor UI through one named place the
/// tests can exercise; the registry tests all pipe and so only ever see [`ask`].
fn initial(seed: &[usize]) -> picker::Selection {
    picker::Selection::ticked(seed)
}

/// Print the preset table and take the selection, re-asking on nonsense.
///
/// `seed` marks the rows the configuration already enables. The table is the
/// tick state the empty answer accepts; a typed answer overrides it, exactly as
/// the picker's buffer does.
fn ask(seed: &[usize], command: &str) -> Result<Vec<usize>, Exit> {
    for (index, preset) in presets::PRESETS.iter().enumerate() {
        println!(
            "{}) [{}] {} {} {} {}{}",
            index + 1,
            if seed.contains(&index) { 'x' } else { ' ' },
            preset.name,
            preset.url,
            if preset.curated { "default" } else { "opt-in" },
            match preset.fingerprints.last().copied() {
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
            // A terminal that closed accepts the ticks, as an empty answer does.
            Ok(0) => return Ok(seed.to_vec()),
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
        // An empty answer takes the ticks; `none` still clears them.
        if line.trim().is_empty() {
            return Ok(seed.to_vec());
        }
        match parse_choice(&line, presets::PRESETS.len()) {
            Ok(chosen) => return Ok(chosen),
            Err(message) => eprintln!("{command}: {message}"),
        }
    }
    Err(Exit::usage(format!(
        "{command}: no valid selection after {SELECT_ATTEMPTS} attempts"
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
async fn apply(
    repo: &Repo,
    chosen: &[usize],
    accept: &std::collections::BTreeMap<String, String>,
    dry_run: bool,
) -> Exit {
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
                preset.fingerprints.last().copied().unwrap_or("tofu")
            );
            continue;
        }
        match install::pin(repo, preset, accept, &BTreeMap::new(), "git time install").await {
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
                // The root the pin just wrote, with its own date: the newly
                // pinned root leads the bundle, so it is the first root — and a
                // leaf never stands in for it. The digest keeps the spelling the
                // preset is written in, so it can be compared with the
                // publication as it stands.
                let label = crate::cmd::anchor::root_certificates(&anchor)
                    .and_then(|roots| roots.into_iter().next())
                    .map_or_else(
                        || "-".to_owned(),
                        |der| {
                            let expiry = x509_cert::Certificate::from_der(&der)
                                .ok()
                                .map(|certificate| {
                                    anchors::expiry_text(
                                        &anchors::not_after(&certificate),
                                        jiff::Timestamp::now(),
                                    )
                                })
                                .unwrap_or_else(|| "-".to_owned());
                            format!(
                                "{} {expiry}",
                                install::digest_for(preset.fingerprints.last().copied(), &der)
                            )
                        },
                    );
                println!(
                    "enabled {} ({}) fingerprint {label}",
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

/// The root a listing shows: the newest one still valid at `now`, and the
/// newest of all when the whole bundle is dead.
///
/// Bundle order is not date order — a rotation appends — so `last()` alone can
/// pick a retired root while a live one sits next to it.
#[must_use]
pub(crate) fn looming(
    roots: &[anchors::RootRow],
    now: jiff::Timestamp,
) -> Option<&anchors::RootRow> {
    let live = roots
        .iter()
        .filter(|root| !anchors::expired(&root.not_after, now))
        .max_by(|left, right| left.not_after.cmp(&right.not_after));
    live.or_else(|| {
        roots
            .iter()
            .max_by(|left, right| left.not_after.cmp(&right.not_after))
    })
}

/// Whether `id`'s anchor at `path` loads.
pub(crate) fn pinned(id: &str, path: &std::path::Path) -> bool {
    AnchorStore::load(&[(id.to_owned(), path.to_path_buf())]).is_ok()
}

/// Whether the bundle at `path` already holds **every** root the blocks name,
/// with at least one of them valid now.
///
/// No named root at all leaves nothing to compare, but any live root will do: a
/// block from before roots were recorded only needs a bundle that can still
/// vouch. Otherwise a partial match is not enough — the missing root still has
/// to be fetched, or the blocks naming it would stay unverifiable — and an
/// all-expired bundle is not enough either, or `restore` would skip a fetch whose
/// whole point is a root that is valid now. Both sides are compared in the
/// length of the named value, so a SHA-1 and a SHA-256 spelling of the same root
/// both count.
fn covers(id: &str, path: &std::path::Path, wanted: &[String]) -> bool {
    if !path.exists() {
        return false;
    }
    let mut store = AnchorStore::default();
    if store.insert(id, path).is_err() {
        return false;
    }
    let Some(anchor) = store.anchor(id) else {
        return false;
    };
    // Bundle order is append order, so the live set is asked for by date.
    let live = anchor.roots_at(jiff::Timestamp::now());
    if live.is_empty() {
        return false;
    }
    if wanted.is_empty() {
        return true;
    }
    let pinned = |value: &str| {
        anchor
            .roots
            .iter()
            .any(|root| crate::cmd::accept::matches(value, root.as_bytes()))
    };
    let live_named = |value: &str| {
        live.iter()
            .any(|root| crate::cmd::accept::matches(value, root.as_bytes()))
    };
    wanted.iter().all(|value| pinned(value)) && wanted.iter().any(|value| live_named(value))
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

#[cfg(test)]
mod tests {
    use super::{accepted, already_enabled, initial, pin_state, rotated};
    use git_time_core::presets;
    use git_time_core::repo::Repo;

    /// Write one local config key of `dir`.
    fn set(dir: &std::path::Path, key: &str, value: &str) {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["config", "--local", key, value])
            .status()
            .expect("git config");
        assert!(status.success(), "configure {key}");
    }

    /// Write `time.tsa.<id>.url` and/or `time.tsa.<id>.anchor` in the local
    /// config of `dir`.
    fn configure(dir: &std::path::Path, id: &str, url: Option<&str>, anchor: Option<&str>) {
        for (field, value) in [("url", url), ("anchor", anchor)] {
            let Some(value) = value else { continue };
            set(dir, &format!("time.tsa.{id}.{field}"), value);
        }
    }

    /// A repository in a fresh temp dir. The caller runs these tests with the
    /// global and system configs nulled, so only the local config is in play.
    fn repository() -> (tempfile::TempDir, Repo) {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(dir.path())
            .status()
            .expect("git init");
        assert!(status.success(), "init");
        let repo = Repo::open(dir.path()).expect("a repository");
        (dir, repo)
    }

    /// The seed holds the configured preset rows in table order, not in the
    /// alphabetical order `tsa_ids` answers in, and a hand-added id is no row.
    #[test]
    fn the_seed_is_the_configured_presets_in_table_order() {
        let (dir, repo) = repository();
        // Reverse of the table, and a hand-added id with no row.
        configure(
            dir.path(),
            "digicert",
            Some("https://tsa.example/digicert"),
            None,
        );
        configure(
            dir.path(),
            "freetsa",
            Some("https://tsa.example/freetsa"),
            None,
        );
        configure(dir.path(), "acme", Some("https://tsa.example/acme"), None);

        assert_eq!(already_enabled(&repo).expect("the seed"), [0, 1]);
    }

    /// A configured unknown id joins the table as a last, custom, TOFU row that
    /// names the section's endpoint and its configured bundle.
    #[test]
    fn a_configured_section_is_a_custom_row_last_with_tofu() {
        let (dir, repo) = repository();
        configure(
            dir.path(),
            "zz-acme",
            Some("https://tsa.acme.example/tsr"),
            Some("bundles/acme.pem"),
        );

        let rows = super::rows(&repo).expect("rows");
        assert_eq!(rows.len(), presets::PRESETS.len() + 1);
        let last = rows.last().expect("a custom row");
        assert_eq!(last.name, "zz-acme");
        assert_eq!(last.url, "https://tsa.acme.example/tsr");
        assert!(last.fingerprints.is_empty(), "an unknown id is TOFU");
        assert_eq!(
            last.anchor_path,
            Some(dir.path().join("bundles/acme.pem").as_path())
        );
        assert!(!last.curated, "a custom row is never a default");
    }

    /// A section with an anchor but no url cannot be enabled, so it is no row.
    #[test]
    fn an_unknown_section_without_a_url_is_no_row() {
        let (dir, repo) = repository();
        configure(dir.path(), "zz-noauth", None, Some("bundles/noauth.pem"));

        let rows = super::rows(&repo).expect("rows");
        assert_eq!(rows.len(), presets::PRESETS.len());
        assert!(rows.iter().all(|row| row.name != "zz-noauth"));
    }

    /// A configured id the table knows overrides its row from the section: the
    /// row must name what the repository actually seals with, and the section's
    /// algorithm, policy and transport win over the published ones.
    #[test]
    fn a_configured_preset_takes_the_section_url_and_path() {
        let (dir, repo) = repository();
        configure(
            dir.path(),
            "freetsa",
            Some("https://mirror.example/tsr"),
            Some("bundles/freetsa.pem"),
        );
        set(dir.path(), "time.tsa.freetsa.alg", "sha512");
        set(dir.path(), "time.tsa.freetsa.policy", "1.2.3.4.9");
        set(dir.path(), "time.tsa.freetsa.insecure-http", "true");
        // A plain-http preset can be un-marked by an explicit `false`.
        configure(
            dir.path(),
            "digicert",
            Some("http://digicert.example"),
            None,
        );
        set(dir.path(), "time.tsa.digicert.insecure-http", "false");
        // An unset key leaves the preset's own value alone.
        configure(dir.path(), "apple", Some("http://apple.example"), None);

        let rows = super::rows(&repo).expect("rows");
        let freetsa: Vec<_> = rows.iter().filter(|row| row.name == "freetsa").collect();
        assert_eq!(freetsa.len(), 1, "no duplicate row");
        assert_eq!(freetsa[0].url, "https://mirror.example/tsr");
        assert_eq!(freetsa[0].alg, "sha512");
        assert_eq!(freetsa[0].policy, Some("1.2.3.4.9"));
        assert!(freetsa[0].insecure_http, "the section marks it plain http");
        assert_eq!(
            freetsa[0].anchor_path,
            Some(dir.path().join("bundles/freetsa.pem").as_path())
        );

        let digicert = rows
            .iter()
            .find(|row| row.name == "digicert")
            .expect("a row");
        assert!(
            presets::find("digicert")
                .expect("a plain-http preset")
                .insecure_http,
            "the preset is plain http before the section says otherwise"
        );
        assert!(
            !digicert.insecure_http,
            "a configured `false` un-marks a plain-http preset"
        );
        assert!(
            rows.iter()
                .find(|row| row.name == "apple")
                .expect("a row")
                .insecure_http,
            "an unset key keeps the preset's own value"
        );
    }

    /// A preset id with an anchor but no url is still a row: the preset
    /// supplies the endpoint, the section the bundle path.
    #[test]
    fn a_preset_with_only_an_anchor_keeps_its_url() {
        let (dir, repo) = repository();
        configure(dir.path(), "cesnet", None, Some("bundles/cesnet.pem"));

        let rows = super::rows(&repo).expect("rows");
        let cesnet: Vec<_> = rows.iter().filter(|row| row.name == "cesnet").collect();
        assert_eq!(cesnet.len(), 1);
        assert_eq!(
            cesnet[0].url,
            presets::find("cesnet").expect("a preset").url
        );
        assert_eq!(
            cesnet[0].anchor_path,
            Some(dir.path().join("bundles/cesnet.pem").as_path())
        );
    }

    /// Custom rows follow the table in id order and never repeat an id.
    #[test]
    fn custom_rows_are_sorted_and_never_duplicate() {
        let (dir, repo) = repository();
        configure(dir.path(), "zz-b", Some("https://tsa.example/b"), None);
        configure(dir.path(), "zz-a", Some("https://tsa.example/a"), None);

        let rows = super::rows(&repo).expect("rows");
        let custom: Vec<&str> = rows
            .iter()
            .skip(presets::PRESETS.len())
            .map(|row| row.name)
            .collect();
        assert_eq!(custom, ["zz-a", "zz-b"]);
    }

    /// The cursor UI opens on the seed. No pty exists in the suite, so the
    /// call site is pinned here instead: `tsa.rs`'s picker branch is this call.
    #[test]
    fn the_picker_opens_on_the_seed() {
        let selection = initial(&[0, 1]);
        assert_eq!(selection.chosen(), [0, 1]);
        assert!(selection.is_chosen(1));
    }

    /// A bare accept is unambiguous only for a selection of one row; two rows
    /// need the id, since only the chosen rows can be fetched.
    #[test]
    fn a_bare_accept_is_read_against_the_chosen_row() {
        let bare = ["AA:BB".to_owned()];
        let one =
            accepted(&bare, &[0], "git time tsa select").expect("one chosen row names the id");
        assert_eq!(one[presets::PRESETS[0].name], "AA:BB");

        let two =
            accepted(&bare, &[0, 1], "git time tsa select").expect_err("two rows are ambiguous");
        assert!(two.message().contains(presets::PRESETS[0].name), "{two:?}");

        let by_id = accepted(&["digicert=AA:BB".to_owned()], &[1], "git time tsa select")
            .expect("the id is taken as given");
        assert_eq!(by_id["digicert"], "AA:BB");
    }

    /// A hand-added, unmeasured row is trust on first use and has no date to
    /// show; a published row with no local certificate only says the date is
    /// missing, and a measured one shows the measurement. No built-in row
    /// publishes nothing any more, so that shape takes a known name.
    #[test]
    fn the_listing_says_why_a_date_is_missing() {
        use crate::cmd::anchors::RootRow;
        use crate::cmd::picker::Cell;

        let custom = presets::Preset {
            name: "unpublished",
            url: "http://tsa.example/tsr",
            anchor_url: "http://tsa.example/tsr",
            chain: &[],
            alg: "sha256",
            policy: None,
            fingerprints: &[],
            insecure_http: true,
            anchor_path: None,
            curated: false,
        };
        // Nothing was asked, which is the only no-date wording a plain run has.
        // An unknown id is TOFU, the picker's own word, not `not pinned`.
        assert_eq!(
            pin_state(&custom, None, Cell::Idle, false, jiff::Timestamp::now()),
            "tofu"
        );

        let published = presets::find("freetsa").expect("a published preset");
        assert_eq!(
            pin_state(published, None, Cell::Idle, false, jiff::Timestamp::now()),
            "-"
        );
        let unpublished_preset = presets::Preset {
            fingerprints: &[],
            ..*published
        };
        assert_eq!(
            pin_state(
                &unpublished_preset,
                None,
                Cell::Idle,
                false,
                jiff::Timestamp::now()
            ),
            "not pinned"
        );

        // The shape `anchors::expiry_text` returns at the caller, short form
        // included, and the local bundle wins over any probe. A fixed instant
        // keeps the verdict off the calendar.
        let soon = jiff::Timestamp::from_second(1_793_000_000).expect("2026-10-26");
        let roots = [RootRow {
            fingerprint: "aa".repeat(32),
            not_after: "2026-12-02".to_owned(),
        }];
        assert_eq!(
            pin_state(&custom, Some(&roots), Cell::Failed, false, soon),
            "2026-12-02 (expires soon)"
        );

        // Without a pin the cell speaks in the picker's words.
        let served = Cell::Known(crate::cmd::probe::Cached {
            not_after: "2041-03-07".to_owned(),
            fingerprint: "aa".repeat(32),
        });
        let now = jiff::Timestamp::now();
        assert_eq!(
            pin_state(&custom, None, served, false, now),
            "fetch 2041-03-07"
        );
        assert_eq!(pin_state(&custom, None, Cell::Pending, false, now), "…");
        assert_eq!(pin_state(&custom, None, Cell::Failed, false, now), "?");
        assert_eq!(pin_state(&custom, None, Cell::Unpublished, false, now), "?");
    }

    /// A custom row has no publication list and no bundle, so its `Idle` cell
    /// must say `tofu`, the picker's word for trust on first use; a built-in
    /// row keeps the listing's missing-date `-` and the picker's `pin -`.
    #[test]
    fn a_custom_row_says_tofu_where_a_builtin_says_a_missing_date() {
        use crate::cmd::picker::Cell;

        let now = jiff::Timestamp::now();
        let custom = presets::Preset {
            name: "zz-acme",
            url: "https://tsa.acme.example/tsr",
            anchor_url: "",
            chain: &[],
            alg: "sha256",
            policy: None,
            fingerprints: &[],
            insecure_http: false,
            anchor_path: None,
            curated: false,
        };
        assert_eq!(pin_state(&custom, None, Cell::Idle, false, now), "tofu");

        let freetsa = presets::find("freetsa").expect("a published preset");
        assert_eq!(pin_state(freetsa, None, Cell::Idle, false, now), "-");
        assert_eq!(
            crate::cmd::picker::trust(freetsa, None, now, Cell::Idle),
            "pin -"
        );
    }

    #[test]
    fn pin_state_judges_a_served_date_against_the_passed_instant() {
        use crate::cmd::picker::Cell;

        let preset = presets::find("freetsa").expect("a published preset");
        let served = Cell::Known(crate::cmd::probe::Cached {
            not_after: "2026-12-02".to_owned(),
            fingerprint: "aa".repeat(32),
        });
        let before = jiff::Timestamp::from_second(1_793_000_000).expect("2026-10-26");
        let after = jiff::Timestamp::from_second(1_800_000_000).expect("2027-01-15");
        assert_eq!(
            pin_state(preset, None, served.clone(), false, before),
            "fetch expires 2026-12-02"
        );
        assert_eq!(
            pin_state(preset, None, served, false, after),
            "fetch EXPIRED"
        );
    }

    /// The `!` a pinned row gets when the authority serves a root no local root
    /// matches: on the rendered state, and on the comparison itself.
    #[test]
    fn a_rotated_authority_is_marked() {
        use crate::cmd::anchors::RootRow;
        use crate::cmd::picker::Cell;
        use crate::cmd::probe::Cached;

        let _guard = crate::cmd::probe::tests::xdg_lock();
        crate::cmd::probe::tests::xdg();
        let _ = crate::cmd::probe::forget("freetsa");
        let now = jiff::Timestamp::now();

        let preset = presets::find("freetsa").expect("a published preset");
        let roots = [RootRow {
            fingerprint: "aa".repeat(32),
            not_after: "2041-03-07".to_owned(),
        }];
        let foreign = Cached {
            not_after: "2035-02-09".to_owned(),
            fingerprint: "cc".repeat(32),
        };
        let held = Cached {
            not_after: "2041-03-07".to_owned(),
            fingerprint: "aa".repeat(32),
        };

        // The served root is no root of the bundle: the rendered state says so.
        assert!(rotated(
            preset,
            Some(&roots),
            Cell::Known(foreign.clone()),
            now
        ));
        let bundle = Some(&roots[..]);
        assert_eq!(
            pin_state(preset, bundle, Cell::Known(foreign.clone()), true, now),
            "2041-03-07 !"
        );
        // The one the bundle holds stays quiet.
        assert!(!rotated(
            preset,
            Some(&roots),
            Cell::Known(held.clone()),
            now
        ));
        assert_eq!(
            pin_state(preset, bundle, Cell::Known(held.clone()), false, now),
            "2041-03-07"
        );

        // A row with no served root of its own keeps the marker from the last
        // cached answer: a failed refresh must not blink it off.
        let _ = crate::cmd::probe::store("freetsa", &foreign, now);
        for cell in [Cell::Failed, Cell::Pending, Cell::Idle, Cell::Unpublished] {
            assert!(
                rotated(preset, Some(&roots), cell, now),
                "the last answer still rotates"
            );
        }
        let _ = crate::cmd::probe::store("freetsa", &held, now);
        for cell in [Cell::Failed, Cell::Pending, Cell::Idle, Cell::Unpublished] {
            assert!(
                !rotated(preset, Some(&roots), cell, now),
                "the last answer is still held"
            );
        }

        // Nothing to compare without a bundle, and no `!` for a row with
        // neither an answer nor a cache entry.
        assert!(!rotated(preset, None, Cell::Known(foreign.clone()), now));
        assert!(!rotated(preset, Some(&[]), Cell::Known(foreign), now));
        let _ = crate::cmd::probe::forget("freetsa");
        for cell in [Cell::Failed, Cell::Pending, Cell::Idle, Cell::Unpublished] {
            assert!(!rotated(preset, Some(&roots), cell, now));
        }
    }
}
