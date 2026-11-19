//! Judge commits concurrently, hand the results back in `rev-list` order.
//!
//! `log` and `verify` only read, and the cost per commit is dominated by the
//! `git` processes they spawn, so a big range is one commit after another with
//! the screen unchanged until the end. The work is independent per commit, so it
//! runs on a small pool; the printer still sees the commits in the order the
//! walk gave them, because a result that overtakes a slow neighbour waits in a
//! buffer until the neighbour is out.
//!
//! The cheap thing to bound is not the queue but the *index*: a worker waits
//! before it hands over a result whose index is far ahead of the one the printer
//! is on, so the pool never gets more than a fixed window ahead of the printer
//! and the buffer holds at most that many results however long the range is.
//! Bounding the channel alone does not do this — the printer drains it faster
//! than results become unprintable, so it never pushes back.
//!
//! One [`Repo`](git_time_core::repo::Repo) is shared by reference: it is `Sync`
//! since the `update-ref` counter became atomic, and the work here only reads
//! through it. The write that does happen — `sigcheck` hashes a checked commit
//! back into the object database — is atomic in git and safe from several
//! threads.
//!
//! A panic in the work does not hang the pool: it is caught and comes back as an
//! error entry for that commit, the same shape a read failure has. A panic in
//! the printer does not hang it either — it leaves the printer through a guard,
//! which wakes every parked worker so the scope can still join them.

use std::collections::BTreeMap;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, PoisonError, mpsc};

/// The most workers a run uses. The per-commit work is process-bound, and past
/// this the extra processes cost more than they win.
const MAX_WORKERS: usize = 8;

/// The printer's progress, and whether it is still there at all.
struct Gate {
    /// Results the printer has emitted, i.e. the index it is on.
    done: Mutex<usize>,
    /// Signalled when `done` advances or when the printer goes away.
    room: Condvar,
    /// Set once the printer is gone, so a parked worker stops waiting.
    closed: AtomicBool,
}

impl Gate {
    /// Whether the printer has left, for whatever reason.
    fn closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Claim the right to hand over `index`, waiting while it is too far ahead.
    /// `false` means the printer is gone and the result is not worth sending.
    fn enter(&self, index: usize, window: usize) -> bool {
        let mut done = self.done.lock().unwrap_or_else(PoisonError::into_inner);
        while !self.closed() && index >= *done + window {
            done = self.room.wait(done).unwrap_or_else(PoisonError::into_inner);
        }
        !self.closed()
    }

    /// Note that `index` and everything below it have been printed.
    fn advance(&self, done_to: usize) {
        // The lock is released while `emit` runs, so printing is never held
        // against a worker; it is taken only to move the count.
        *self.done.lock().unwrap_or_else(PoisonError::into_inner) = done_to;
        self.room.notify_all();
    }
}

/// Tells the pool on the way out — normal or unwinding — that the printer is
/// gone.
///
/// Without it a printer that panics (a failing `println!`, say) leaves its
/// workers parked in [`Gate::enter`], and the scope join waits for them
/// forever.
struct Closer<'a>(&'a Gate);

impl Drop for Closer<'_> {
    fn drop(&mut self) {
        // The flag is set while holding the lock, and `enter` checks it while
        // holding it too: a worker that has decided to wait cannot miss the
        // wake-up here.
        let _held = self.0.done.lock();
        self.0.closed.store(true, Ordering::Relaxed);
        self.0.room.notify_all();
    }
}

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
    if oids.is_empty() {
        return;
    }
    let workers = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(MAX_WORKERS)
        .min(oids.len())
        .max(1);
    let next = AtomicUsize::new(0);
    // How far the pool may run ahead of the printer, in commits. Generous per
    // worker: a head that is seconds slower than the rest would otherwise park
    // the pool and turn the tail into a second, serial run. Even at the cap the
    // window is a few hundred kept results, far below a long range.
    let window = workers * 32;
    let gate = Gate {
        done: Mutex::new(0),
        room: Condvar::new(),
        closed: AtomicBool::new(false),
    };
    let (sender, receiver) = mpsc::channel::<(usize, Result<T, String>)>();
    let work = &work;

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let sender = sender.clone();
            let next = &next;
            let gate = &gate;
            scope.spawn(move || {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(oid) = oids.get(index) else {
                        break;
                    };
                    let outcome = panic::catch_unwind(AssertUnwindSafe(|| work(oid)))
                        .unwrap_or_else(|payload| Err(panic_message(payload.as_ref())));
                    // Wait for room only *after* the work: a worker that is still
                    // computing is never parked, and the lowest index can always
                    // go through, so the wait cannot deadlock.
                    if !gate.enter(index, window) || sender.send((index, outcome)).is_err() {
                        break;
                    }
                }
            });
        }
        // Required, not a tidy-up: the receiver loop ends when every sender is
        // gone, and the scope keeps this one alive around the workers.
        drop(sender);

        // Results can arrive out of order; the buffer holds the ones whose turn
        // has not come. `enter` above is what keeps that set at `window`.
        let mut buffer: BTreeMap<usize, Result<T, String>> = BTreeMap::new();
        let mut next_emit = 0;
        let _closer = Closer(&gate);
        for (index, outcome) in receiver {
            buffer.insert(index, outcome);
            while let Some(outcome) = buffer.remove(&next_emit) {
                emit(next_emit, outcome);
                next_emit += 1;
                gate.advance(next_emit);
            }
        }
    });
}

/// The text of a caught panic payload.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    let message = payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "panicked without a message".to_owned());
    format!("the judgment panicked: {message}")
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

    /// The pool stays a window ahead of the printer instead of running the whole
    /// range out while the head is slow — the buffer cannot grow with `oids`.
    #[test]
    fn the_pool_does_not_run_away_from_a_slow_printer() {
        let total = 1200;
        let oids: Vec<String> = (0..total).map(|index| index.to_string()).collect();
        let finished = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        ordered(
            &oids,
            |oid| {
                // The first is slow enough that an unbounded pool would finish
                // every other commit before it comes back.
                if oid == "0" {
                    std::thread::sleep(std::time::Duration::from_millis(400));
                }
                finished.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
            |index, _| {
                let ahead = finished.load(Ordering::Relaxed).saturating_sub(index + 1);
                peak.fetch_max(ahead, Ordering::Relaxed);
            },
        );
        // The window per worker, plus up to one result each worker is holding
        // before it can wait.
        let bound = super::MAX_WORKERS * 33;
        let peak = peak.load(Ordering::Relaxed);
        assert!(peak <= bound, "{peak} results ran ahead, bound {bound}");
        assert!(peak > 1, "the head really did hold the others back: {peak}");
    }

    /// A printer that panics does not leave its workers parked in the gate: the
    /// run fails promptly instead of hanging the join.
    #[test]
    fn a_printing_panic_does_not_hang_the_pool() {
        let oids: Vec<String> = (0..600).map(|index| index.to_string()).collect();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ordered(
                &oids,
                |oid| {
                    // Long enough that the others overtake and start to park.
                    if oid == "0" {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                    Ok(())
                },
                |index, _| {
                    // Slow printing, so the pool fills its window and parks while
                    // the printer is still near the head.
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    if index == 40 {
                        panic!("printer died");
                    }
                },
            );
        }));
        assert!(outcome.is_err());
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
                    assert_eq!(error, "the judgment panicked: boom");
                }
            },
        );
        assert_eq!(emitted.load(Ordering::Relaxed), oids.len());
    }
}
