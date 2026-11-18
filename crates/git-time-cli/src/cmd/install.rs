//! `git time install`: wire the hooks and pin authorities.
//!
//! What is always wired are the two hooks a commit actually needs: `post-commit`
//! for an ordinary commit and `post-merge` for a merge, which never runs
//! `post-commit`. `pre-commit` and `pre-merge-commit` are wired only under
//! `time.gate = pre-commit`, so a repository that does not want the hard gate
//! carries no extra hook.
//!
//! A foreign hook at any of those names is not overwritten: it is renamed next to
//! the shim as `<name>.pre-time` — or the next free `<name>.pre-time.<n>` when a
//! husky or pre-commit-framework run regenerated the hook since the last install
//! — and the shim runs it first, propagating its failure. The summary names every
//! preserve, so a user can see both originals survive. The hooks directory is the
//! one `git rev-parse --git-path hooks` answers, so a `core.hooksPath` from husky
//! or the pre-commit framework is where the shims land — not `.git/hooks`, which
//! those tools never run.
//!
//! `--preset public` (the default) configures the public authorities and fetches
//! their anchors into the user's config directory. Existing `time.tsa.<id>.*`
//! keys are left exactly as they are, so a working configuration survives a
//! second run. A fetch that fails only warns: the hooks are still worth wiring,
//! and `doctor` names the missing bundle. When the failure leaves an anchor path
//! missing under the gate, the summary says loudly that commits will be refused.
//! A fetched bundle is parsed into certificates before it replaces the pinned
//! one, so prose cannot masquerade as an anchor. `--preset none` or `--no-tsa`
//! writes no authority at all.

use std::path::{Path, PathBuf};

use clap::ValueEnum;
use git_time_core::presets::{self, Preset as Authority};
use git_time_core::repo::Repo;
use git_time_core::trust::AnchorStore;

use crate::cmd::{Exit, anchors, git_stdout, hooks, open};

/// Which authorities `install` configures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Preset {
    /// The public FreeTSA and rfc3161.ai.moda authorities.
    Public,
    /// No authority at all.
    None,
}

/// What pinning one authority came to.
pub(crate) struct Pinned {
    /// The config id.
    pub(crate) id: &'static str,
    /// How many of its config keys were already set and left alone.
    pub(crate) kept: usize,
    /// Where its anchor is expected, and whether that path is now missing.
    pub(crate) missing_anchor: Option<PathBuf>,
}

/// Run `git time install`.
pub async fn run(directory: Option<std::path::PathBuf>, preset: Preset, no_tsa: bool) -> Exit {
    let repo = match open(directory) {
        Ok(repo) => repo,
        Err(exit) => return exit,
    };
    let dir = match hooks::hooks_dir(&repo) {
        Ok(dir) => dir,
        Err(exit) => return exit,
    };
    let created = !dir.exists();
    if let Err(error) = std::fs::create_dir_all(&dir) {
        return Exit::config(format!(
            "cannot create the hooks directory {}: {error}",
            dir.display()
        ));
    }

    let gated = match gate_enabled(&repo) {
        Ok(gated) => gated,
        Err(exit) => return exit,
    };
    let wired = if gated {
        hooks::ALL_HOOKS.to_vec()
    } else {
        hooks::POST_HOOKS.to_vec()
    };

    let mut preserved = Vec::new();
    for name in &wired {
        match hooks::wire(&dir, name) {
            Ok(Some(chained)) => preserved.push(format!("{name} -> {chained}")),
            Ok(None) => {}
            Err(exit) => return exit,
        }
    }

    let preset = if no_tsa { Preset::None } else { preset };
    let authorities: &[Authority] = match preset {
        Preset::Public => &presets::PRESETS,
        Preset::None => &[],
    };
    let mut kept = 0_usize;
    let mut unpinned = Vec::new();
    for authority in authorities {
        match pin(&repo, authority).await {
            Ok(pinned) => {
                kept += pinned.kept;
                if let Some(path) = pinned.missing_anchor {
                    unpinned.push((pinned.id, path));
                }
            }
            Err(exit) => return exit,
        }
    }

    if crate::cmd::doctor::binary_on_path().is_none() {
        eprintln!(
            "rfc3161: warning: git-time is not on PATH; the hooks will do nothing until it is"
        );
    }

    println!(
        "hooks dir: {}{}",
        dir.display(),
        if created { " (created)" } else { "" }
    );
    println!("wired: {}", wired.join(", "));
    if !preserved.is_empty() {
        println!("preserved: {}", preserved.join(", "));
    }
    println!(
        "tsa: {} configured{}",
        authorities.len(),
        if kept > 0 {
            format!(" ({kept} existing key(s) kept)")
        } else {
            String::new()
        }
    );
    for (id, path) in &unpinned {
        if gated {
            eprintln!(
                "rfc3161: warning: no anchor for `{id}` at {}; with time.gate = pre-commit every \
                 commit will be refused until it is pinned (run: git time install once the fetch works)",
                path.display()
            );
        } else {
            eprintln!(
                "rfc3161: warning: no anchor for `{id}` at {}; tokens of that authority cannot be \
                 verified until it is pinned",
                path.display()
            );
        }
    }
    Exit::ok()
}

/// Write the config of `authority` that is not set yet, and try to pin its
/// anchor.
///
/// A key that is already set is left alone, so a working configuration is not
/// clobbered. The config is written even when the fetch fails, so the authority
/// is listed and `doctor` can report the missing anchor instead of the entry
/// vanishing.
///
/// The anchor lands where the policy will read it: an already configured
/// `time.tsa.<id>.anchor` path wins over the default
/// `$XDG_CONFIG_HOME/git-time/anchors/<id>.pem`, because a freshly fetched
/// bundle the policy never looks at would print a fingerprint of the wrong file.
pub(crate) async fn pin(repo: &Repo, authority: &Authority) -> Result<Pinned, Exit> {
    let base = format!("time.tsa.{}", authority.name);
    // Read before writing: the key may be set already and is then the target.
    let configured = anchors::configured(repo)?
        .into_iter()
        .find(|anchor| anchor.id == authority.name)
        .map(|anchor| anchor.path);
    let path = match configured {
        Some(path) => path,
        None => anchors::dir().join(format!("{}.pem", authority.name)),
    };
    if let Some(parent) = path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return Err(Exit::config(format!(
            "cannot create the anchors directory {}: {error}",
            parent.display()
        )));
    }
    let anchor_path = path.to_string_lossy().into_owned();
    let mut fields = vec![
        ("url", authority.url.to_owned()),
        ("alg", authority.alg.to_owned()),
        ("anchor", anchor_path),
    ];
    if let Some(policy) = authority.policy {
        fields.push(("policy", policy.to_owned()));
    }
    let mut kept = 0_usize;
    for (field, value) in fields {
        if set(repo, &format!("{base}.{field}"), &value)? {
            kept += 1;
        }
    }

    let mut missing_anchor = None;
    match anchors::fetch(authority.anchor_url).await {
        Ok(bytes) => match install_anchor(authority.name, &path, &bytes) {
            // The fingerprint of the first certificate, the same value
            // `anchor list` and the lock carry, not of the whole file: a bundle
            // may append chain certificates and would otherwise get two hashes.
            Ok(fingerprint) => println!(
                "anchor {}: {} sha256 {}",
                authority.name,
                path.display(),
                fingerprint
            ),
            Err(error) => eprintln!(
                "rfc3161: warning: the anchor of `{}` from {} is unusable: {error}",
                authority.name, authority.anchor_url
            ),
        },
        Err(error) => eprintln!(
            "rfc3161: warning: cannot fetch the anchor of `{}` from {}: {error}",
            authority.name, authority.anchor_url
        ),
    }
    if !path.exists() {
        missing_anchor = Some(path);
    }
    Ok(Pinned {
        id: authority.name,
        kept,
        missing_anchor,
    })
}

/// Parse `bytes` as `id`'s bundle before it replaces what is pinned at `path`.
///
/// The bundle is staged next to the target and moved over it only after
/// [`AnchorStore::load`] accepted every certificate, so a fetch that returned
/// prose or a truncated block leaves the previous anchor untouched.
fn install_anchor(id: &str, path: &Path, bytes: &[u8]) -> Result<String, String> {
    let staging = path.with_extension("pem.new");
    std::fs::write(&staging, bytes)
        .map_err(|error| format!("cannot write {}: {error}", staging.display()))?;
    if let Err(error) = AnchorStore::load(&[(id.to_owned(), staging.clone())]) {
        let reason = error.to_string();
        // A previous anchor is never replaced by an unparseable bundle; when
        // there is none, the bad bytes are kept so doctor can name them as
        // unparseable instead of as a fetch that never happened.
        if path.exists() {
            let _ = std::fs::remove_file(&staging);
        } else {
            let _ = std::fs::rename(&staging, path);
        }
        return Err(reason);
    }
    let fingerprint = crate::cmd::anchor::first_certificate(bytes)
        .map(|der| anchors::fingerprint(&der))
        .ok_or_else(|| format!("{} carried no certificate", path.display()))?;
    std::fs::rename(&staging, path).map_err(|error| {
        let _ = std::fs::remove_file(&staging);
        format!("cannot write {}: {error}", path.display())
    })?;
    Ok(fingerprint)
}

/// Set one repository-local config key unless it is already set.
///
/// Returns whether an existing value was kept. `--replace-all` would flatten a
/// hand-tuned value (a different mirror, a longer timeout) on every run, so the
/// keys are only written when absent.
fn set(repo: &Repo, key: &str, value: &str) -> Result<bool, Exit> {
    match git_stdout(repo, &["config", "--local", "--get", key]) {
        Ok(existing) if !existing.trim().is_empty() => Ok(true),
        Ok(_) => {
            git_stdout(repo, &["config", "--local", key, value])?;
            Ok(false)
        }
        // git exits 1 for an unset key, which `git_stdout` reports as usage.
        Err(exit) if exit.code() == 2 => {
            git_stdout(repo, &["config", "--local", key, value])?;
            Ok(false)
        }
        Err(exit) => Err(exit),
    }
}

/// Whether `time.gate = pre-commit` is configured.
fn gate_enabled(repo: &Repo) -> Result<bool, Exit> {
    Ok(repo
        .config_non_empty("time.gate")
        .map_err(Exit::config)?
        .is_some_and(|value| value.eq_ignore_ascii_case("pre-commit")))
}
