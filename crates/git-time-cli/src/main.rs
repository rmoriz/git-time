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

/// Command line surface of git-time.
#[derive(Debug, Parser)]
#[command(
    name = "git time",
    version,
    about = "RFC 3161 timestamp evidence for commits",
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
        /// Which authorities to configure.
        #[arg(long, value_enum, default_value = "public")]
        preset: cmd::install::Preset,
        /// Write no authority config (same as `--preset none`).
        #[arg(long)]
        no_tsa: bool,
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

fn main() -> ExitCode {
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
            commits,
        } => cmd::verify::run(
            directory,
            range,
            require_sealed,
            require_signed,
            commits,
            json,
        ),
        Command::Log {
            range,
            json,
            commits,
        } => cmd::log::run(directory, range, commits, json),
        Command::Install { preset, no_tsa } => cmd::install::run(directory, preset, no_tsa).await,
        Command::Uninstall { force } => cmd::uninstall::run(directory, force),
        Command::Doctor { json } => cmd::doctor::run(directory, json),
        Command::Tsa { command } => cmd::tsa::run(directory, command).await,
        Command::Anchor { command } => cmd::anchor::run(directory, command).await,
    }
}
