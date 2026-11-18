//! `git time uninstall`: take the shims back out.
//!
//! Every hook of ours is removed, whichever of the four it is — a repository that
//! switched `time.gate` after installing still has all of them. A hook we did not
//! write is left alone, and a hook preserved as `<name>.pre-time` (or
//! `<name>.pre-time.<n>`) is restored by a rename, so its bytes and mode come
//! back exactly.
//!
//! A shim the user edited by hand is not removed on a guess: it is named and left
//! in place. `--force` moves it to the next free preserve and restores the
//! original, so the edit is kept too — or, when nothing was ever preserved, it
//! stays where it is and the output says so instead of renaming it onto itself
//! and back.
//!
//! Running it twice is a success: the second run finds nothing of ours and does
//! nothing.

use crate::cmd::{Exit, hooks, open};

/// Run `git time uninstall`.
pub fn run(directory: Option<std::path::PathBuf>, force: bool) -> Exit {
    let repo = match open(directory) {
        Ok(repo) => repo,
        Err(exit) => return exit,
    };
    let dir = match hooks::hooks_dir(&repo) {
        Ok(dir) => dir,
        Err(exit) => return exit,
    };

    let mut removed = 0_usize;
    let mut restored = 0_usize;
    let mut edited = Vec::new();
    let mut left = Vec::new();
    for name in hooks::ALL_HOOKS {
        match hooks::unwire(&dir, name, force) {
            Ok(hooks::Removal::NotOurs) => {}
            Ok(hooks::Removal::Removed { restored: from }) => {
                removed += 1;
                if from.is_some() {
                    restored += 1;
                }
            }
            Ok(hooks::Removal::Modified) => {
                edited.push(name);
                eprintln!(
                    "rfc3161: warning: the {name} hook was edited by hand and is left in place; \
                     run: git time uninstall --force to replace it with the preserved original"
                );
            }
            Ok(hooks::Removal::LeftInPlace) => {
                left.push(name);
                println!("left in place: {name} (no preserved original to restore)");
            }
            Ok(hooks::Removal::Replaced {
                moved,
                restored: from,
            }) => {
                removed += 1;
                if from.is_some() {
                    restored += 1;
                }
                println!("kept the edited {name} hook as {moved}");
            }
            Err(exit) => return exit,
        }
    }

    if removed == 0 && edited.is_empty() && left.is_empty() {
        println!("nothing to do: no git-time hooks in {}", dir.display());
    } else {
        println!("removed {removed} hook(s), restored {restored}");
        if !edited.is_empty() {
            println!("left in place (edited): {}", edited.join(", "));
        }
        if !left.is_empty() {
            println!("left in place: {}", left.join(", "));
        }
    }
    Exit::ok()
}
