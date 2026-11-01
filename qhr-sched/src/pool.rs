//! Persistent worker pool for `Scheduler::superpose`.
//!
//! Thread spawn is the latency floor of the scoped-thread path (about
//! 300 us per 8-branch collapse on Windows). A pool keeps N workers parked
//! on their own channels; a collapse costs N channel sends and N wakeups
//! instead of N thread creations.
//!
//! Soundness contract (the only unsafe in qhr): a branch job borrows the
//! cell and its input from the caller's stack frame. The job is erased to
//! `'static` so it can cross into a long-lived worker, and `superpose`
//! does not return until `Completion::wait` has seen every dispatched job
//! finish (the counter is decremented by the worker AFTER the job has been
//! dropped). That is exactly the guarantee `std::thread::scope` gives via
//! join, made explicit. Nothing else ever holds a job.
//!
//! One channel per worker, round-robin dispatch: no shared queue lock, no
//! contention between branches of one collapse. Workers that die (a job
//! that panics outside `catch_unwind`, which the scheduler never does) are
//! detected on the next send and the job falls back to a one-off thread,
//! so a dead worker degrades latency rather than correctness.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};

pub(crate) type Job = Box<dyn FnOnce() + Send + 'static>;

/// Counts outstanding jobs of one collapse; `wait` blocks until zero.
pub(crate) struct Completion {
    pending: AtomicUsize,
    lock: Mutex<()>,
    cv: Condvar,
}

impl Completion {
    pub(crate) fn new(n: usize) -> Arc<Self> {
        Arc::new(Self {
            pending: AtomicUsize::new(n),
            lock: Mutex::new(()),
            cv: Condvar::new(),
        })
    }
    /// Called by the worker after the job has returned and been dropped.
    pub(crate) fn one_done(&self) {
        if self.pending.fetch_sub(1, Ordering::AcqRel) == 1 {
            let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
            self.cv.notify_all();
        }
    }
    pub(crate) fn wait(&self) {
        // Fast path: usually every job has already reported through the
        // result channel by the time we get here, so the counter is zero.
        let mut g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        while self.pending.load(Ordering::Acquire) != 0 {
            g = self.cv.wait(g).unwrap_or_else(|p| p.into_inner());
        }
    }
}

struct Worker {
    tx: mpsc::Sender<(Job, Arc<Completion>)>,
}

pub struct Pool {
    workers: Vec<Worker>,
    next: AtomicUsize,
}

impl Pool {
    /// `n` parked workers. Threads are named `qhr-worker-<i>` and are
    /// detached; dropping the pool closes their channels and they exit.
    pub fn new(n: usize) -> Arc<Pool> {
        let n = n.max(1);
        let workers = (0..n)
            .map(|i| {
                let (tx, rx) = mpsc::channel::<(Job, Arc<Completion>)>();
                std::thread::Builder::new()
                    .name(format!("qhr-worker-{i}"))
                    .spawn(move || {
                        for (job, done) in rx {
                            job();
                            // `job` was consumed above; the closure and every
                            // borrow it carried are gone before we report.
                            done.one_done();
                        }
                    })
                    .expect("spawn qhr worker");
                Worker { tx }
            })
            .collect();
        Arc::new(Pool {
            workers,
            next: AtomicUsize::new(0),
        })
    }

    /// Sized to the machine: one worker per hardware thread.
    pub fn per_core() -> Arc<Pool> {
        Pool::new(
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(2),
        )
    }

    pub fn len(&self) -> usize {
        self.workers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.workers.is_empty()
    }

    /// Hand one job to the next worker. If that worker is gone, run the job
    /// on a one-off thread so the collapse still completes.
    pub(crate) fn dispatch(&self, job: Job, done: Arc<Completion>) {
        let i = self.next.fetch_add(1, Ordering::Relaxed) % self.workers.len();
        if let Err(mpsc::SendError((job, done))) = self.workers[i].tx.send((job, done)) {
            std::thread::spawn(move || {
                job();
                done.one_done();
            });
        }
    }
}
