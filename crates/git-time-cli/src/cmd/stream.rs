//! Judge commits concurrently, hand the results back in `rev-list` order.
//!
//! `log` and `verify` only read, and the cost per commit is dominated by the
//! `git` processes they spawn, so a big range is one commit after another with
//! the screen unchanged until the end. The work is independent per commit, so it
//! runs on a small pool; the printer still sees the commits in the order the
//! walk gave them, because a result that overtakes a slow neighbour waits in a
//! buffer until the neighbour is out.
//!
//! Every worker holds its own [`Repo`](git_time_core::repo::Repo) handle: the
//! handle carries a `Cell` of `update-ref` attempts, so it is not `Sync`, but a
//! clone is cheap and read-only work never touches that counter. Writes that do
//! happen — `sigcheck` hashes a checked commit back into the object database —
//! are atomic in git and safe from several threads.
//!
//! A panic in the work does not hang the pool: it is caught and comes back as an
//! error entry for that commit, the same shape a read failure has.

use std::collections::BTreeMap;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

/// The most workers a run uses. The per-commit work is process-bound, and past
/// this the extra processes cost more than they win.
const MAX_WORKERS: usize = 8;

/// Run `work` for every oid on a bounded pool, calling `emit` in oid order.
///
/// `work` gets one oid and returns either its result or a reason it failed.
/// `emit` is called exactly once per oid, in order, with the index it had in
/// `oids` — a caller that needs a running verdict can keep it between calls.
pub(crate) fn ordered<T, F, E>(oids: &[String], work: F, mut emit: E)
where
    T: Send,
    F: Fn(&str) -> Result<T, String> + Sync,
    E: FnMut(usize, Result<T, String>),
{
    let workers = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(MAX_WORKERS)
        .min(oids.len())
        .max(1);
    let next = AtomicUsize::new(0);
    let (sender, receiver) = mpsc::channel::<(usize, Result<T, String>)>();
    let work = &work;

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let sender = sender.clone();
            let next = &next;
            scope.spawn(move || {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(oid) = oids.get(index) else {
                        break;
                    };
                    let outcome = panic::catch_unwind(AssertUnwindSafe(|| work(oid)))
                        .unwrap_or_else(|payload| Err(panic_message(&payload)));
                    if sender.send((index, outcome)).is_err() {
                        break;
                    }
                }
            });
        }
        // The scope keeps one sender alive itself, so the loop below only ends
        // when every worker has dropped its clone.
        drop(sender);

        // Results can arrive out of order; the buffer holds the ones whose turn
        // has not come, which is a handful at most (one per worker).
        let mut buffer: BTreeMap<usize, Result<T, String>> = BTreeMap::new();
        let mut next_emit = 0;
        for (index, outcome) in receiver {
            buffer.insert(index, outcome);
            while let Some(outcome) = buffer.remove(&next_emit) {
                emit(next_emit, outcome);
                next_emit += 1;
            }
        }
    });
}

/// The text of a caught panic payload.
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "panicked without a message".to_owned())
}

#[cfg(test)]
mod tests {
    use super::ordered;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A slow early commit does not let a fast later one past it.
    #[test]
    fn results_come_back_in_order() {
        let oids: Vec<String> = (0..24).map(|index| index.to_string()).collect();
        let seen = Mutex::new(Vec::new());
        ordered(
            &oids,
            |oid| {
                // The first is by far the slowest, so the rest queue up behind it.
                let wait = if oid == "0" { 120 } else { 1 };
                std::thread::sleep(std::time::Duration::from_millis(wait));
                Ok(oid.to_owned())
            },
            |index, outcome| {
                let oid = outcome.expect("the work never fails here");
                assert_eq!(index.to_string(), oid);
                seen.lock().expect("lock").push(oid);
            },
        );
        assert_eq!(*seen.lock().expect("lock"), oids);
    }

    /// A panicking commit is one error entry, not a lost index that stalls the
    /// printer behind it.
    #[test]
    fn a_panic_becomes_an_error_entry() {
        let oids: Vec<String> = (0..8).map(|index| index.to_string()).collect();
        let emitted = AtomicUsize::new(0);
        ordered(
            &oids,
            |oid| {
                if oid == "3" {
                    panic!("boom");
                }
                Ok(oid.to_owned())
            },
            |_, outcome| {
                emitted.fetch_add(1, Ordering::Relaxed);
                if let Err(error) = outcome {
                    assert_eq!(error, "boom");
                }
            },
        );
        assert_eq!(emitted.load(Ordering::Relaxed), oids.len());
    }
}
