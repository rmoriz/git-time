//! The commands and the small pieces they share.

pub mod accept;
pub mod anchor;
pub mod anchors;
pub mod doctor;
pub mod drop;
pub mod hook;
pub mod hooks;
pub mod install;
pub mod log;
pub mod picker;
pub mod seal;
pub mod stream;
pub mod tsa;
pub mod uninstall;
pub mod verify;

use std::path::{Path, PathBuf};

use git_time_core::repo::Repo;

/// How a command ended: the exit code and, when there is one, the line to say
/// about it.
///
/// The code is carried rather than printed where it is decided, so a caller can
/// keep printing its own per-commit lines and still end on the right status.
#[derive(Debug)]
pub struct Exit {
    code: u8,
    message: Option<String>,
}

impl Exit {
    /// Success without a word.
    #[must_use]
    pub fn ok() -> Self {
        Self {
            code: 0,
            message: None,
        }
    }

    /// Success or failure with an explicit code and a line on stderr.
    ///
    /// An empty `message` is not printed: a caller that already said its line
    /// passes the code on with `String::new()` rather than repeating it.
    #[must_use]
    pub fn with(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: Some(message.into()),
        }
    }

    /// A usage or configuration problem: exit `2`.
    #[must_use]
    pub fn usage(message: impl Into<String>) -> Self {
        Self::with(2, message)
    }

    /// A configuration problem: exit `2`, prefixed like every other message.
    #[must_use]
    pub fn config(error: impl std::fmt::Display) -> Self {
        Self::usage(format!("git time: {error}"))
    }

    /// An evidence or seal failure: exit `1`.
    #[must_use]
    pub fn seal(message: impl Into<String>) -> Self {
        Self::with(1, message)
    }

    /// The exit code this ends on.
    #[must_use]
    pub fn code(&self) -> u8 {
        self.code
    }

    /// The line this wants said, if any.
    #[must_use]
    pub fn message(&self) -> String {
        self.message.clone().unwrap_or_default()
    }

    /// Print the message, if there is one, and hand back the code.
    ///
    /// A message that is already empty — a line the caller printed itself — is
    /// not printed again, so a failure is exactly one line, never an extra
    /// blank one.
    #[must_use]
    pub fn report(self) -> u8 {
        if let Some(message) = &self.message
            && !message.is_empty()
        {
            eprintln!("{message}");
        }
        self.code
    }
}

/// Open the repository a command was pointed at: `-C DIR`, else the working
/// directory, which is where git runs a hook.
pub fn open(directory: Option<PathBuf>) -> Result<Repo, Exit> {
    let path = match directory {
        Some(path) => path,
        None => std::env::current_dir()
            .map_err(|error| Exit::config(format!("cannot read the working directory: {error}")))?,
    };
    Repo::open(&path).map_err(Exit::config)
}

/// The object id HEAD names right now, if it names one.
pub fn head_commit(repo: &Repo) -> Result<Option<String>, Exit> {
    match repo.head().map_err(Exit::config)? {
        git_time_core::repo::Head::Detached(oid) => Ok(Some(oid)),
        git_time_core::repo::Head::Symref(name) => repo.resolve_ref(&name).map_err(Exit::config),
    }
}

/// Point HEAD itself at `oid`, detaching it without touching index or worktree.
pub fn detach_head(repo: &Repo, oid: &str) -> Result<(), Exit> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo.path())
        .args(["update-ref", "--no-deref", "HEAD", oid])
        .output()
        .map_err(|error| Exit::config(format!("cannot run git: {error}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Exit::config(format!(
            "cannot detach HEAD: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// Put HEAD back the way it was found.
pub fn restore_head(repo: &Repo, head: &git_time_core::repo::Head) -> Result<(), Exit> {
    let output = match head {
        git_time_core::repo::Head::Symref(name) => std::process::Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(["symbolic-ref", "HEAD", name])
            .output(),
        git_time_core::repo::Head::Detached(oid) => std::process::Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(["update-ref", "--no-deref", "HEAD", oid])
            .output(),
    }
    .map_err(|error| Exit::config(format!("cannot run git: {error}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Exit::config(format!(
            "cannot restore HEAD: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// Run git in `repo` and hand back stdout, or git's stderr as a usage error.
pub fn git_stdout(repo: &Repo, args: &[&str]) -> Result<String, Exit> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo.path())
        .args(args)
        .output()
        .map_err(|error| Exit::config(format!("cannot run git: {error}")))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(Exit::usage(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// The path git keeps `name` at inside this repository, resolved against the
/// repository.
///
/// `rev-parse --git-path` answers a path relative to the working directory
/// during a rebase, so a relative answer is joined to `repo` first. That makes
/// this correct for a linked worktree too, where the git directory is a file
/// somewhere else: git decides, not a hard-coded `.git` join.
pub fn git_path(repo: &Repo, name: &str) -> Result<PathBuf, Exit> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo.path())
        .args(["rev-parse", "--git-path", name])
        .output()
        .map_err(|error| Exit::config(format!("cannot run git: {error}")))?;
    if !output.status.success() {
        return Err(Exit::config(format!(
            "cannot resolve the git path of {name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let raw = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let path = Path::new(&raw);
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo.path().join(path)
    })
}

/// The repository path git reports for an internal path, resolved against the
/// repository, and whether that path exists.
///
/// Used to tell an in-progress rebase from an idle one.
#[must_use]
pub fn git_path_exists(repo: &Repo, name: &str) -> Option<PathBuf> {
    let path = git_path(repo, name).ok()?;
    path.exists().then_some(path)
}

/// The first seven characters of an object id, for text meant for a person.
#[must_use]
pub fn short(oid: &str) -> &str {
    oid.get(..7).unwrap_or(oid)
}

/// The commits a read-only command was pointed at.
///
/// An explicit rev-range is walked newest first, `HEAD` when nothing is given
/// (the default range), and every `commits` argument is resolved to the commit
/// it names. Duplicates are dropped, keeping the first position, so naming a
/// commit that the range already contains does not judge it twice.
pub fn targets(
    repo: &Repo,
    command: &str,
    range: Option<&str>,
    commits: &[String],
) -> Result<Vec<String>, Exit> {
    let mut oids: Vec<String> = Vec::new();
    if let Some(range) = range {
        for line in git_stdout(repo, &["rev-list", range])?.lines() {
            oids.push(line.trim().to_owned());
        }
    } else if commits.is_empty() {
        // Only a HEAD that names nothing means "no commits"; any other failure
        // of the walk (a corrupt object, a dangling HEAD) keeps git's stderr.
        if git_stdout(repo, &["rev-parse", "--verify", "HEAD"]).is_err() {
            return Err(Exit::usage(format!(
                "git time {command}: HEAD names no commit — the repository has no commits"
            )));
        }
        for line in git_stdout(repo, &["rev-list", "HEAD"])?.lines() {
            oids.push(line.trim().to_owned());
        }
    }
    for rev in commits {
        let spec = format!("{rev}^{{commit}}");
        let oid = git_stdout(repo, &["rev-parse", "--verify", "--end-of-options", &spec])
            .map_err(|_| Exit::usage(format!("git time {command}: `{rev}` is not a commit")))?;
        oids.push(oid.trim().to_owned());
    }
    let mut seen = std::collections::BTreeSet::new();
    oids.retain(|oid| seen.insert(oid.clone()));
    Ok(oids)
}
