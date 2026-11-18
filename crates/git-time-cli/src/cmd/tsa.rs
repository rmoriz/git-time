//! `git time tsa`: the registry of timestamp authorities.
//!
//! An authority is a `time.tsa.<id>` section of the **local** repository
//! config; `add` writes it, `list` reads it, `remove` deletes it whole. Nothing
//! here talks to the network — `preset add` is the one exception and goes
//! through the same fetch path `install --preset` uses.
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

use std::path::PathBuf;

use clap::Subcommand;
use git_time_core::imprint::{Alg, Digest};
use git_time_core::presets;
use git_time_core::repo::Repo;
use git_time_core::trust::AnchorStore;
use git_time_core::tsa::StampRequest;
use serde_json::{Value, json};

use crate::cmd::{Exit, anchors, git_stdout, install, open};

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
        rows.push((id, url, alg, anchor, anchored, fingerprint));
    }

    if json {
        let rows: Vec<Value> = rows
            .iter()
            .map(|(id, url, alg, anchor, anchored, fingerprint)| {
                json!({
                    "id": id,
                    "url": url,
                    "alg": alg,
                    "anchor": anchor.to_string_lossy(),
                    "anchored": anchored,
                    "fingerprint": fingerprint,
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
        for (id, url, alg, anchor, anchored, fingerprint) in &rows {
            println!(
                "{id} {url} {alg} {} {} ({})",
                anchor.display(),
                fingerprint.as_deref().unwrap_or("-"),
                if *anchored { "anchored" } else { "missing" }
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
            "{} {} {} ({})",
            preset.name,
            preset.url,
            preset.alg,
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
    let pinned = match install::pin(repo, preset).await {
        Ok(pinned) => pinned,
        Err(exit) => return exit,
    };
    println!("tsa {}: {} configured", preset.name, preset.url);
    if pinned.kept > 0 {
        println!("tsa {}: {} existing key(s) kept", preset.name, pinned.kept);
    }
    if let Some(path) = pinned.missing_anchor {
        eprintln!(
            "rfc3161: warning: no anchor for `{}` at {}; tokens of that authority cannot be verified until it is pinned",
            preset.name,
            path.display()
        );
        // Unlike `install`, where the hooks are still worth wiring, a one-off
        // `preset add` exists to pin: without an anchor it did not do its job.
        return Exit::seal(String::new());
    }
    Exit::ok()
}

/// Whether `id`'s anchor at `path` loads.
fn pinned(id: &str, path: &std::path::Path) -> bool {
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
