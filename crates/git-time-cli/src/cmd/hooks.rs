//! The hook shims `install` writes and `uninstall` takes back, and the states
//! `doctor` reads them in.
//!
//! A shim is POSIX `sh` and does exactly three things: run a foreign hook that
//! was there before, in the same event, and propagate its exit status; run this
//! binary's hook; and exit `0` when `git-time` is not on `PATH`, so an install on
//! a machine where the binary later disappears does not turn every commit into a
//! hook failure.
//!
//! **The foreign hook runs first for `pre-*` too**, not only for the post hooks.
//! A failing linter must still block the commit, and a gate that ran after it
//! would let the linter work once per commit even when the gate then refuses.
//! Ours never touches the index or the worktree, so running second cannot change
//! what the foreign hook sees.
//!
//! The foreign hook is preserved next to the shim and restored by a plain
//! rename, which is what makes `uninstall` byte-identical. The first one goes to
//! `<name>.pre-time`; a husky or pre-commit-framework run that regenerates the
//! hook is preserved as the next free `<name>.pre-time.<n>` instead of being
//! renamed over an existing preserve — the user's first original is never lost,
//! and the shim chains the newest one.
//!
//! A preserved name is only ever a name this module chose and wrote into a shim,
//! so the shim content is how the active one is found again.

use std::path::{Path, PathBuf};

use git_time_core::repo::Repo;

use crate::cmd::{Exit, git_path};

/// The hooks that seal a commit: an ordinary commit runs `post-commit`, a merge
/// never does and runs `post-merge` instead.
pub const POST_HOOKS: [&str; 2] = ["post-commit", "post-merge"];

/// The hooks that gate a commit, wired only under `time.gate = pre-commit`. A
/// merge runs `pre-merge-commit` where a commit runs `pre-commit`.
pub const PRE_HOOKS: [&str; 2] = ["pre-commit", "pre-merge-commit"];

/// Every hook this tool may own.
pub const ALL_HOOKS: [&str; 4] = [
    "post-commit",
    "post-merge",
    "pre-commit",
    "pre-merge-commit",
];

/// The suffix a displaced foreign hook is preserved under.
pub const CHAINED_SUFFIX: &str = ".pre-time";

/// The shim for `name`, chaining `<name>.pre-time`.
///
/// This is the canonical shim: a repository that never had a foreign hook, or
/// only the first one, gets exactly these bytes.
///
/// No bashism, no heredoc: `dirname`/`[ -x ]`/`command -v` only. `$0` keeps the
/// chained lookup next to the shim itself, so a `core.hooksPath` directory works
/// the same as `.git/hooks`.
#[must_use]
pub fn shim(name: &str) -> String {
    shim_chaining(name, &format!("{name}{CHAINED_SUFFIX}"))
}

/// The shim for `name`, chaining the preserved file `chained` by that name.
#[must_use]
pub fn shim_chaining(name: &str, chained: &str) -> String {
    format!(
        "#!/bin/sh\n\
         chained=\"$(dirname \"$0\")/{chained}\"\n\
         if [ -x \"$chained\" ]; then \"$chained\" \"$@\" || exit $?; fi\n\
         command -v git-time >/dev/null 2>&1 && exec git-time hook {name} \"$@\"; exit 0\n"
    )
}

/// The hooks directory of `repo`, resolved by git so `core.hooksPath` is honoured.
pub fn hooks_dir(repo: &Repo) -> Result<PathBuf, Exit> {
    git_path(repo, "hooks")
}

/// Where the first displaced hook for `name` lives.
#[must_use]
pub fn chained(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}{CHAINED_SUFFIX}"))
}

/// Whether `path` exists, following no symlink: a dangling link counts.
fn lexists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Whether `path` is a symlink whose target does not exist.
fn is_dangling(path: &Path) -> bool {
    lexists(path) && !path.exists()
}

/// Whether `path` may be executed.
fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

/// Every preserved name for `name` that exists, oldest first: `<name>.pre-time`
/// is the first one ever written, the numbered ones follow in ascending order.
/// The last entry is therefore always the newest.
#[must_use]
pub fn preserved_names(dir: &Path, name: &str) -> Vec<String> {
    let prefix = format!("{name}{CHAINED_SUFFIX}");
    let mut names = Vec::new();
    if lexists(&chained(dir, name)) {
        names.push(prefix.clone());
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return names;
    };
    let numbered = format!("{prefix}.");
    let mut rest: Vec<(u64, String)> = Vec::new();
    for entry in entries.flatten() {
        let file = entry.file_name().to_string_lossy().into_owned();
        let Some(digits) = file.strip_prefix(&numbered) else {
            continue;
        };
        if let Ok(index) = digits.parse::<u64>() {
            rest.push((index, file));
        }
    }
    rest.sort();
    names.extend(rest.into_iter().map(|(_, file)| file));
    names
}

/// The newest preserved name for `name`, if any.
///
/// The newest one is the hook the tool last displaced, so it is the one a shim
/// must chain when it has no chain of its own: a stale `<name>.pre-time` from a
/// tool that has since regenerated its hook must not be resurrected.
fn newest_preserved(dir: &Path, name: &str) -> Option<String> {
    preserved_names(dir, name).into_iter().next_back()
}

/// The next preserved name that is free, without touching anything.
fn next_free_preserved(dir: &Path, name: &str) -> Result<String, Exit> {
    let first = format!("{name}{CHAINED_SUFFIX}");
    if !lexists(&dir.join(&first)) {
        return Ok(first);
    }
    for index in 1..=u32::MAX {
        let candidate = format!("{first}.{index}");
        if !lexists(&dir.join(&candidate)) {
            return Ok(candidate);
        }
    }
    Err(Exit::config(format!(
        "no free preserved name for the {name} hook in {}",
        dir.display()
    )))
}

/// The preserved name the content of `path` chains, if any.
fn chained_by(dir: &Path, name: &str, content: &str) -> Option<String> {
    if content == shim(name) {
        return Some(format!("{name}{CHAINED_SUFFIX}"));
    }
    preserved_names(dir, name)
        .into_iter()
        .find(|candidate| content == shim_chaining(name, candidate))
}

/// An older version's shim for `name`: no chaining at all, hence exact bytes.
///
/// Matched exactly rather than by a substring, so a hand-edited old shim is not
/// mistaken for an untouched one.
fn is_legacy(content: &str, name: &str) -> bool {
    content.trim_end() == format!("#!/bin/sh\nexec git-time hook {name} \"$@\"")
}

/// Whether `path` holds a shim of ours for `name`.
///
/// The exact current content counts — with whichever preserved name it chains —
/// and so does the older shim an upgrade may still find: it is recognised by its
/// exact bytes, so an upgrade rewrites it instead of chaining our own old shim in
/// front of the new one.
#[must_use]
pub fn is_ours(path: &Path, name: &str) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    if is_legacy(&content, name) {
        return true;
    }
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    content == shim(name) || chained_by(dir, name, &content).is_some()
}

/// What doctor found at one hook name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Our shim, without a preserved foreign hook.
    Ours,
    /// Our shim with a preserved foreign hook in front of it.
    Chained,
    /// Something that is not our shim.
    Foreign,
    /// Nothing there.
    Absent,
    /// Our shim, or the hook it chains, lost its execute bit.
    NotExecutable,
    /// A symlink whose target is gone.
    Dangling,
}

impl State {
    /// The word doctor prints.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ours => "ours",
            Self::Chained => "chained",
            Self::Foreign => "foreign",
            Self::Absent => "absent",
            Self::NotExecutable => "not-executable",
            Self::Dangling => "dangling",
        }
    }

    /// Whether our shim is in place.
    #[must_use]
    pub fn wired(self) -> bool {
        matches!(self, Self::Ours | Self::Chained)
    }
}

/// The state of `name` in `dir`.
#[must_use]
pub fn state(dir: &Path, name: &str) -> State {
    let target = dir.join(name);
    if is_dangling(&target) {
        return State::Dangling;
    }
    if !target.exists() {
        return State::Absent;
    }
    if !is_ours(&target, name) {
        return State::Foreign;
    }
    if !is_executable(&target) {
        return State::NotExecutable;
    }
    let content = std::fs::read_to_string(&target).unwrap_or_default();
    if let Some(preserved) = chained_by(dir, name, &content) {
        let path = dir.join(&preserved);
        if !lexists(&path) {
            return State::Ours;
        }
        if is_dangling(&path) {
            return State::Dangling;
        }
        if !is_executable(&path) {
            return State::NotExecutable;
        }
        return State::Chained;
    }
    State::Ours
}

/// The file that makes `state` say [`State::NotExecutable`], if any: our shim
/// or the preserve it chains.
#[must_use]
pub fn not_executable(dir: &Path, name: &str) -> Option<PathBuf> {
    let target = dir.join(name);
    if target.exists() && !is_executable(&target) {
        return Some(target);
    }
    let content = std::fs::read_to_string(&target).ok()?;
    let preserved = chained_by(dir, name, &content)?;
    let path = dir.join(preserved);
    (path.exists() && !is_executable(&path)).then_some(path)
}

/// Make `path` executable by its owner, group and others, the mode git expects
/// of a hook.
fn make_executable(path: &Path) -> Result<(), Exit> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).map_err(
            |error| {
                Exit::config(format!(
                    "cannot make {} executable: {error}",
                    path.display()
                ))
            },
        )?;
    }
    Ok(())
}

/// Write the shim for `name` into `dir`, preserving a foreign hook first.
///
/// Nothing is ever renamed over an existing preserve: a second foreign hook goes
/// to the next free `<name>.pre-time.<n>` and the shim chains that one, so the
/// first original survives a tool that regenerates its hook between installs.
///
/// Idempotent: an existing shim is rewritten to the same bytes and keeps
/// chaining whatever it chained, an old-version shim is rewritten rather than
/// chained. Returns the preserved name when one was newly created.
pub fn wire(dir: &Path, name: &str) -> Result<Option<String>, Exit> {
    let target = dir.join(name);
    let existing = std::fs::read_to_string(&target).ok();
    let ours = target.exists() && is_ours(&target, name);

    let mut chained = if ours {
        existing
            .as_deref()
            .and_then(|content| chained_by(dir, name, content))
    } else {
        None
    };
    if chained.is_none() {
        // A preserved hook from an earlier run is still the one to chain, even
        // when the shim in front of it was an old version's — the newest, so a
        // stale preserve is not resurrected over a fresher one.
        chained = newest_preserved(dir, name);
    }

    let mut created = None;
    if target.exists() && !ours {
        let preserved = next_free_preserved(dir, name)?;
        std::fs::rename(&target, dir.join(&preserved)).map_err(|error| {
            Exit::config(format!(
                "cannot preserve the foreign {name} hook as {preserved}: {error}"
            ))
        })?;
        eprintln!("rfc3161: preserved the foreign {name} hook as {preserved}");
        chained = Some(preserved.clone());
        created = Some(preserved);
    }

    let content = chained
        .as_deref()
        .map_or_else(|| shim(name), |file| shim_chaining(name, file));
    std::fs::write(&target, content)
        .map_err(|error| Exit::config(format!("cannot write the {name} hook: {error}")))?;
    make_executable(&target)?;
    Ok(created)
}

/// How `unwire` ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Removal {
    /// Nothing of ours at that name.
    NotOurs,
    /// Our shim was removed, and a preserved hook restored when one was found.
    Removed {
        /// The preserved name that was restored, if any.
        restored: Option<String>,
    },
    /// A modified shim was left in place; nothing was restored.
    Modified,
    /// A modified shim with no preserved original was left in place on `force`.
    LeftInPlace,
    /// A modified shim was moved to `moved` before its preserve was restored.
    Replaced {
        /// The preserved name the edited shim now lives under.
        moved: String,
        /// The preserved name that was restored, if any.
        restored: Option<String>,
    },
}

/// Rename the preserved hook of `name` back; the caller has freed the name.
///
/// `preferred` is the preserve the shim chained, and is used when it still
/// exists; otherwise the newest remaining preserve is restored.
fn restore(dir: &Path, name: &str, preferred: Option<&str>) -> Result<Option<String>, Exit> {
    let source = preferred
        .map(str::to_owned)
        .filter(|candidate| lexists(&dir.join(candidate)))
        .or_else(|| newest_preserved(dir, name));
    let Some(source) = source else {
        return Ok(None);
    };
    std::fs::rename(dir.join(&source), dir.join(name)).map_err(|error| {
        Exit::config(format!(
            "cannot restore the preserved {source} as the {name} hook: {error}"
        ))
    })?;
    Ok(Some(source))
}

/// Remove our shim for `name` and restore a preserved hook, if any.
///
/// Only an exact shim of ours (with whichever preserve it chains) or the exact
/// older shim is removed. A hand-edited shim is reported as [`Removal::Modified`]
/// and left in place; with `force` it is moved to the next free preserve first,
/// so the edit is kept and the original is still restored — unless nothing was
/// ever preserved, in which case there is nothing to restore and the shim is
/// left exactly where it is ([`Removal::LeftInPlace`]).
pub fn unwire(dir: &Path, name: &str, force: bool) -> Result<Removal, Exit> {
    let target = dir.join(name);
    let Ok(content) = std::fs::read_to_string(&target) else {
        return Ok(Removal::NotOurs);
    };

    let exact = content == shim(name) || chained_by(dir, name, &content).is_some();
    if !exact && !is_legacy(&content, name) {
        if !force {
            return Ok(Removal::Modified);
        }
        // Renaming and immediately restoring would put the same bytes back: with
        // no original to restore, the edited shim belongs where it is and the
        // hook stays wired.
        let Some(original) = newest_preserved(dir, name) else {
            return Ok(Removal::LeftInPlace);
        };
        let moved = next_free_preserved(dir, name)?;
        std::fs::rename(&target, dir.join(&moved)).map_err(|error| {
            Exit::config(format!(
                "cannot preserve the modified {name} hook as {moved}: {error}"
            ))
        })?;
        // `moved` is the newest file now, so the original is named explicitly.
        let restored = restore(dir, name, Some(&original))?;
        return Ok(Removal::Replaced { moved, restored });
    }

    let preferred = chained_by(dir, name, &content);
    std::fs::remove_file(&target)
        .map_err(|error| Exit::config(format!("cannot remove the {name} hook: {error}")))?;
    let restored = restore(dir, name, preferred.as_deref())?;
    Ok(Removal::Removed { restored })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `shim` and `shim_chaining` with the canonical name are the same bytes.
    #[test]
    fn the_canonical_shim_is_the_chaining_one() {
        assert_eq!(
            shim("post-commit"),
            shim_chaining("post-commit", "post-commit.pre-time")
        );
    }

    /// A numbered preserve is chained by its own name.
    #[test]
    fn a_numbered_preserve_is_chained_by_name() {
        let shim = shim_chaining("post-commit", "post-commit.pre-time.2");
        assert!(shim.contains("post-commit.pre-time.2"), "{shim}");
    }

    /// The older shim shape is recognised exactly, not by substring.
    #[test]
    fn a_legacy_shim_is_only_the_known_shape() {
        assert!(is_legacy(
            "#!/bin/sh\nexec git-time hook post-commit \"$@\"\n",
            "post-commit"
        ));
        assert!(!is_legacy(
            "#!/bin/sh\nPATH=/x:$PATH\nexec git-time hook post-commit \"$@\"\n",
            "post-commit"
        ));
    }
}
