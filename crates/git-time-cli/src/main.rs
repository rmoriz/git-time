//! `git time` — the command git dispatches to.
//!
//! This is the hook entrypoint, the explicit `seal` command, `drop`, the judges
//! (`verify`, `log`), the installation plumbing (`install`, `uninstall`,
//! `doctor`), and the authority registry (`tsa`, `anchor`).
//!
//! A repository needs **two** hooks to be sealed: `post-commit` for ordinary
//! commits and `post-merge` for merges, which never run `post-commit` (measured
//! on 2.56). A further two, `pre-commit` and `pre-merge-commit`, are only the gate
//! for `time.gate = pre-commit` and are harmless otherwise. `git time install`
//! wires exactly the set the repository's gate calls for.
//!
//! Exit codes are one contract for every command: `0` success (a skip is a
//! success), `1` evidence or seal failure, `2` usage or configuration. The hook
//! exits `3` on failure only when `time.on-failure = fail`, because git ignores
//! a post-commit exit status and only a wrapper reads it; its gate is the real
//! stop and exits `1`.

mod cmd;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use cmd::Exit;

/// What `-V` and `--version` print.
///
/// A timestamp tool is asked to be auditable, so its version line says who
/// wrote it, under which licence, and where the source is — the answers a
/// reader would otherwise have to hunt for.
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\nCopyright (C) 2026 Roland Moriz\n",
    "License GPL-2.0-only: GNU GPL version 2 \
     <https://www.gnu.org/licenses/old-licenses/gpl-2.0.html>\n",
    "No warranty, not even for merchantability or fitness for a particular purpose.\n",
    "https://github.com/rmoriz/git-time",
);

/// The quick start printed under both `-h` and `--help`.
///
/// Kept to the two things a first-time reader needs: the three commands that
/// set the repository up, and where the evidence goes. Everything deeper is in
/// the manual, which the last line names.
const QUICK_START: &str = "\
Quick start:
  git time tsa select    pick authorities; each chosen anchor is pinned
  git time install       wire the hooks (git-time must be on PATH)
  git commit -m \"...\"    the only command you type from then on
  git time verify        judge the evidence; run it in CI

Evidence is written into the commit as X-RFC3161-* trailers before the
commit lands, covered by its signature, and a commit already on a remote is
left alone. A dead authority costs evidence, never the commit.

`git time doctor` names why nothing is sealing, `git time tsa select` is the
repair path, and docs/manual.md has the configuration and the failure modes.";

/// Command line surface of git-time.
#[derive(Debug, Parser)]
#[command(
    name = "git time",
    version = VERSION,
    long_version = VERSION,
    about = "RFC 3161 timestamp evidence for commits",
    after_help = QUICK_START,
    disable_help_subcommand = true
)]
struct Cli {
    /// Run in the repository at this directory instead of the current one.
    #[arg(short = 'C', value_name = "DIR", global = true)]
    directory: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Git hook entrypoint.
    Hook {
        /// The hook event: `post-commit`, `post-merge` or `pre-commit`.
        event: String,
        /// Whatever git passes after the event (`post-merge 0` for a merge,
        /// `post-merge 1` for a squash).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Seal a commit (HEAD by default) with the configured authorities.
    Seal {
        /// A git rev-range; every commit in it is sealed, oldest first.
        #[arg(long, value_name = "RANGE")]
        range: Option<String>,
        /// Re-seal commits that already carry matching evidence, and seal
        /// commits dropped on purpose.
        #[arg(long)]
        force: bool,
    },
    /// Leave the next commit unsealed on purpose.
    Drop,
    /// Judge the evidence of commits.
    ///
    /// Read-only apart from the signature check, which may leave one loose
    /// object behind (`hash-object -w`); refs, index and worktree stay put.
    Verify {
        /// A git rev-range; every commit in it is judged, newest first.
        #[arg(long, value_name = "RANGE")]
        range: Option<String>,
        /// Fail an unsealed commit (a gate: the verdict stays `unsealed`).
        #[arg(long)]
        require_sealed: bool,
        /// Fail an unsigned commit (a gate: the verdict stays what it is).
        #[arg(long)]
        require_signed: bool,
        /// Print the findings as one JSON document.
        #[arg(long)]
        json: bool,
        /// Print a POSIX `sh` script that re-verifies the tokens of ONE commit
        /// with `openssl` instead of this tool (needs `openssl` with `ts` and
        /// `zstd`). Nothing is run.
        #[arg(long, conflicts_with_all = ["json", "range"])]
        openssl: bool,
        /// Commits to judge, on top of any range (HEAD when neither is given).
        #[arg(value_name = "COMMIT")]
        commits: Vec<String>,
    },
    /// List evidence per commit.
    ///
    /// `log` is a record; it exits 0 when it could read everything. Use
    /// `git time verify` to gate CI.
    Log {
        /// A git rev-range; every commit in it is listed, newest first.
        #[arg(long, value_name = "RANGE")]
        range: Option<String>,
        /// Print the evidence as one JSON document.
        #[arg(long)]
        json: bool,
        /// Commits to list, on top of any range (HEAD when neither is given).
        #[arg(value_name = "COMMIT")]
        commits: Vec<String>,
    },
    /// Wire the hooks into this repository.
    ///
    /// Two hooks are required — `post-commit` and `post-merge` — plus
    /// `pre-commit` and `pre-merge-commit` for the gate.
    Install {
        /// Write no authority config; keep whatever is configured.
        #[arg(long)]
        no_tsa: bool,
        /// Accept the root of a rotation, as `<id>=<fingerprint>`.
        #[arg(long, value_name = "ID=FINGERPRINT")]
        accept: Vec<String>,
    },
    /// Unwire the hooks again and restore the ones that were displaced.
    Uninstall {
        /// Also remove a shim that was edited by hand (it is kept, next to the
        /// restored original).
        #[arg(long)]
        force: bool,
    },
    /// Report configuration and anchor health.
    Doctor {
        /// Print the report as one JSON object.
        #[arg(long)]
        json: bool,
    },
    /// Manage timestamp authorities.
    Tsa {
        #[command(subcommand)]
        command: cmd::tsa::Command,
    },
    /// Manage pinned anchor certificates.
    Anchor {
        #[command(subcommand)]
        command: cmd::anchor::Command,
    },
}

#[cfg(unix)]
unsafe extern "C" {
    /// `signal(2)`; the two constants below are all this needs of it.
    fn signal(number: i32, handler: usize) -> usize;
}

/// `SIGPIPE`, which Rust masks by default.
#[cfg(unix)]
const SIGPIPE: i32 = 13;

/// `SIG_DFL`.
#[cfg(unix)]
const SIG_DFL: usize = 0;

fn main() -> ExitCode {
    // `verify` and `log` stream, so `| head` is a normal way to read them. With
    // Rust's ignored SIGPIPE the write past `head` panics with a broken pipe and
    // exit 101; the default disposition ends the process quietly, and no caller
    // of a streaming reader wants more than that.
    #[cfg(unix)]
    // SAFETY: `SIG_DFL` is always a valid handler for `SIGPIPE`.
    unsafe {
        signal(SIGPIPE, SIG_DFL);
    }
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("git time: cannot start the async runtime: {error}");
            return ExitCode::from(1);
        }
    };
    let exit = runtime.block_on(dispatch(cli));
    ExitCode::from(exit.report())
}

/// Route one parsed command; every route returns an [`Exit`], never panics.
async fn dispatch(cli: Cli) -> Exit {
    let directory = cli.directory;
    match cli.command {
        Command::Hook { event, rest } => match event.as_str() {
            "post-commit" => cmd::hook::run(directory, cmd::hook::Event::PostCommit, false).await,
            "post-merge" => {
                // git passes `1` for a squash, where no commit exists yet.
                let squash = rest.iter().any(|arg| arg == "1");
                cmd::hook::run(directory, cmd::hook::Event::PostMerge, squash).await
            }
            "pre-commit" => cmd::hook::run(directory, cmd::hook::Event::PreCommit, false).await,
            "pre-merge-commit" => {
                cmd::hook::run(directory, cmd::hook::Event::PreMergeCommit, false).await
            }
            other => Exit::usage(format!("git time hook: unknown event `{other}`")),
        },
        Command::Seal { range, force } => cmd::seal::run(directory, range, force).await,
        Command::Drop => cmd::drop::run(directory).await,
        Command::Verify {
            range,
            require_sealed,
            require_signed,
            json,
            openssl,
            commits,
        } => cmd::verify::run(
            directory,
            range,
            require_sealed,
            require_signed,
            commits,
            json,
            openssl,
        ),
        Command::Log {
            range,
            json,
            commits,
        } => cmd::log::run(directory, range, commits, json),
        Command::Install { no_tsa, accept } => cmd::install::run(directory, no_tsa, &accept).await,
        Command::Uninstall { force } => cmd::uninstall::run(directory, force),
        Command::Doctor { json } => cmd::doctor::run(directory, json),
        Command::Tsa { command } => cmd::tsa::run(directory, command).await,
        Command::Anchor { command } => cmd::anchor::run(directory, command).await,
    }
}
