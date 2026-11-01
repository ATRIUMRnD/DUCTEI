//! qhr-sched: speculative fan-out, verified commit, DUCTEI-persisted receipt.
//!
//! `superpose` runs up to `fan_out` branches of one `Cell` on scoped OS
//! threads (no runtime, no allocator-heavy executor), returns the first
//! output that passes `Cell::verify`, and cancels the rest. The result is a
//! `Collapse`: the winning output (if any) plus a `CollapseReceipt` that
//! records every branch's hashes, timing and fate.
//!
//! `commit` writes the receipt into a DUCTEI `Channel` as an ordinary
//! `Envelope`, so QHR has no log of its own: DUCTEI's append-only JSONL,
//! causal-delta gate and scope policy are the durable, tamper-evident
//! record. `verify_chain` replays those envelopes and recomputes the hash
//! chain, which is the check a ward/QFLTL integrity pass runs.
//!
//! Real-time rules enforced here:
//!   0. Fan-out is capped (default `available_parallelism * 2`). Extra
//!      inputs are reported as `Pruned`, never silently dropped.
//!   1. A branch finishing after the `Deadline` is `Expired` and its
//!      output is never looked at, even if it would have verified.
//!   2. Branch time is measured against `Cell::budget` and recorded as
//!      `over_budget`, so budget drift shows up in the receipt timeline.

use ductei_core::{Channel, ChannelError, Envelope};
use qhr_cell::{hash_value, Cell, Clock, Ctx, Deadline, Hash, MonotonicClock};
use serde::{Deserialize, Serialize};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

pub mod pool;
pub mod weight;
pub use pool::Pool;
pub use weight::BranchWeighter;

pub const RECEIPT_SCOPE: &str = "qhr.receipt";
pub const RECEIPT_KEY_PREFIX: &str = "qhr/collapse/";
pub const RECEIPT_SCHEMA: u16 = 1;
const DOMAIN_IN: &str = "qhr.in.v1";
const DOMAIN_OUT: &str = "qhr.out.v1";
const DOMAIN_RECEIPT: &str = "qhr.receipt.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Fate {
    /// Verified first; its output is the collapse result.
    Won,
    /// Finished after a winner was already chosen; output not examined.
    Lost,
    /// Finished but `verify` returned false.
    Rejected,
    /// Finished after the deadline; output discarded unread.
    Expired,
    /// Asked to stop via `Ctx` and the scheduler never received a result
    /// (channel closed). Should not occur with scoped threads; kept so a
    /// receipt can never claim a fate it did not observe.
    Cancelled,
    /// Never started: over the fan-out cap.
    Pruned,
    /// The cell panicked. Reported, never propagated.
    Panicked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchReceipt {
    pub idx: u32,
    pub weight: f32,
    pub in_hash: Hash,
    pub out_hash: Option<Hash>,
    pub fate: Fate,
    pub elapsed_us: u64,
    pub over_budget: bool,
    /// Weighter class for this branch, so a replay can rebuild the learned
    /// prior. Omitted from the serialized form when `None`, which keeps
    /// receipts written before this field byte-identical (same hash).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollapseReceipt {
    pub cell: String,
    pub prev: Hash,
    pub deadline_us: u64,
    pub budget_us: u64,
    pub fan_out_cap: u32,
    pub branches: Vec<BranchReceipt>,
    pub winner: Option<u32>,
    /// Hash over everything above; the next receipt's `prev`.
    pub hash: Hash,
}

impl CollapseReceipt {
    /// Recompute `hash` from the other fields.
    pub fn compute_hash(&self) -> Result<Hash, serde_json::Error> {
        let mut body = self.clone();
        body.hash = Hash::ZERO;
        hash_value(DOMAIN_RECEIPT, &body)
    }
}

#[derive(Debug)]
pub struct Collapse<Out> {
    pub output: Option<Out>,
    pub receipt: CollapseReceipt,
}

/// One speculative input with an optional weight (J-space likelihood,
/// Jev score, or 1.0). Branches are tried in descending weight; weight
/// only orders and prunes, it never changes what `verify` accepts.
#[derive(Debug, Clone)]
pub struct Branch<In> {
    pub input: In,
    pub weight: f32,
}
impl<In> From<In> for Branch<In> {
    fn from(input: In) -> Self {
        Branch { input, weight: 1.0 }
    }
}

#[derive(Clone)]
pub struct Scheduler {
    pub fan_out_cap: u32,
    pub clock: Arc<dyn Clock>,
    /// Persistent workers. `None` = one scoped thread per branch (simple,
    /// zero shared state, ~300 us per collapse). `Some` = dispatch to parked
    /// workers (sub-100 us target). Same semantics either way.
    pub pool: Option<Arc<Pool>>,
}

impl Default for Scheduler {
    fn default() -> Self {
        let n = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2) as u32;
        Self {
            fan_out_cap: n.saturating_mul(2).max(1),
            clock: Arc::new(MonotonicClock),
            pool: None,
        }
    }
}

enum Msg<Out> {
    Done {
        idx: u32,
        out: Out,
        elapsed: Duration,
        finished: Instant,
    },
    Panicked {
        idx: u32,
        elapsed: Duration,
    },
}

impl Scheduler {
    pub fn with_fan_out(mut self, cap: u32) -> Self {
        self.fan_out_cap = cap.max(1);
        self
    }

    /// Run branches on `pool` instead of spawning a thread per branch.
    pub fn with_pool(mut self, pool: Arc<Pool>) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Run `branches` of `cell` speculatively; return the first verified
    /// output and a receipt chained onto `prev`.
    pub fn superpose<C: Cell>(
        &self,
        cell: &C,
        branches: Vec<Branch<C::In>>,
        deadline: Deadline,
        prev: Hash,
    ) -> Collapse<C::Out> {
        let budget = cell.budget();
        let start = self.clock.now();

        // Order by weight, stable so equal weights keep caller order.
        let mut order: Vec<usize> = (0..branches.len()).collect();
        order.sort_by(|&a, &b| {
            branches[b]
                .weight
                .partial_cmp(&branches[a].weight)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut receipts: Vec<BranchReceipt> = branches
            .iter()
            .enumerate()
            .map(|(i, b)| BranchReceipt {
                idx: i as u32,
                weight: b.weight,
                in_hash: hash_value(DOMAIN_IN, &b.input).unwrap_or(Hash::ZERO),
                out_hash: None,
                fate: Fate::Pruned,
                elapsed_us: 0,
                over_budget: false,
                class: None,
            })
            .collect();

        let active: Vec<usize> = order
            .iter()
            .copied()
            .take(self.fan_out_cap as usize)
            .collect();
        for &i in &active {
            receipts[i].fate = Fate::Cancelled;
        }

        let ctx = Ctx::new();
        let (tx, rx) = mpsc::channel::<Msg<C::Out>>();
        let winner: Mutex<Option<(u32, C::Out)>> = Mutex::new(None);

        // One branch, on whatever thread runs it. Sends exactly one message.
        let run_branch = |i: usize, tx: mpsc::Sender<Msg<C::Out>>, ctx: Ctx| {
            let input = &branches[i].input;
            let t0 = self.clock.now();
            let r =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cell.run(&ctx, input)));
            let finished = self.clock.now();
            let elapsed = finished.duration_since(t0);
            let msg = match r {
                Ok(out) => Msg::Done {
                    idx: i as u32,
                    out,
                    elapsed,
                    finished,
                },
                Err(_) => Msg::Panicked {
                    idx: i as u32,
                    elapsed,
                },
            };
            let _ = tx.send(msg);
        };

        // The scheduler side: classify every active branch's message.
        let collect = |receipts: &mut Vec<BranchReceipt>| {
            let mut winner = winner.lock().unwrap_or_else(|p| p.into_inner());
            let mut remaining = active.len();
            while remaining > 0 {
                let wait = deadline.remaining(self.clock.as_ref());
                let msg = if winner.is_some() || wait.is_zero() {
                    // Winner chosen or deadline passed: every active branch
                    // has been told to stop via `Ctx`. Every branch is waited
                    // for regardless (scope join, or the pool's Completion),
                    // so take each one's message and classify it honestly. A
                    // cell that ignores `Ctx` delays collapse until it
                    // returns; that is the cooperative-cancel contract.
                    if winner.is_some() {
                        ctx.cancel();
                    }
                    match rx.recv() {
                        Ok(m) => m,
                        Err(_) => break,
                    }
                } else {
                    match rx.recv_timeout(wait) {
                        Ok(m) => m,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                };
                remaining -= 1;
                match msg {
                    Msg::Panicked { idx, elapsed } => {
                        let r = &mut receipts[idx as usize];
                        r.fate = Fate::Panicked;
                        r.elapsed_us = elapsed.as_micros() as u64;
                        r.over_budget = elapsed > budget;
                    }
                    Msg::Done {
                        idx,
                        out,
                        elapsed,
                        finished,
                    } => {
                        let r = &mut receipts[idx as usize];
                        r.elapsed_us = elapsed.as_micros() as u64;
                        r.over_budget = elapsed > budget;
                        if finished >= deadline.0 {
                            r.fate = Fate::Expired;
                            continue;
                        }
                        if winner.is_some() {
                            // Not hashed or verified: once a branch has won,
                            // spending time on the losers delays the caller.
                            r.fate = Fate::Lost;
                            continue;
                        }
                        r.out_hash = hash_value(DOMAIN_OUT, &out).ok();
                        let input = &branches[idx as usize].input;
                        if cell.verify(input, &out) {
                            r.fate = Fate::Won;
                            *winner = Some((idx, out));
                            ctx.cancel();
                        } else {
                            r.fate = Fate::Rejected;
                        }
                    }
                }
            }
            // Past the deadline with no winner: stop the stragglers.
            ctx.cancel();
        };

        match &self.pool {
            Some(pool) => {
                let done = pool::Completion::new(active.len());
                for &i in &active {
                    let tx = tx.clone();
                    let ctx = ctx.clone();
                    let run = &run_branch;
                    let job: Box<dyn FnOnce() + Send + '_> = Box::new(move || run(i, tx, ctx));
                    // SAFETY: the job borrows `cell`, `branches`, `self.clock`
                    // and `run_branch`, all of which outlive this function
                    // body. `done.wait()` below blocks until the worker has
                    // run AND dropped every dispatched job, so no borrow is
                    // alive when this frame returns. Same contract as
                    // `std::thread::scope`, enforced by `Completion`.
                    let job: pool::Job = unsafe {
                        std::mem::transmute::<Box<dyn FnOnce() + Send + '_>, pool::Job>(job)
                    };
                    pool.dispatch(job, Arc::clone(&done));
                }
                drop(tx);
                collect(&mut receipts);
                done.wait();
            }
            None => {
                std::thread::scope(|s| {
                    for &i in &active {
                        let tx = tx.clone();
                        let ctx = ctx.clone();
                        let run = &run_branch;
                        s.spawn(move || run(i, tx, ctx));
                    }
                    drop(tx);
                    collect(&mut receipts);
                });
            }
        }

        let winner = winner.into_inner().unwrap_or_else(|p| p.into_inner());
        let mut receipt = CollapseReceipt {
            cell: cell.name().to_string(),
            prev,
            deadline_us: deadline.0.saturating_duration_since(start).as_micros() as u64,
            budget_us: budget.as_micros() as u64,
            fan_out_cap: self.fan_out_cap,
            branches: receipts,
            winner: winner.as_ref().map(|(i, _)| *i),
            hash: Hash::ZERO,
        };
        receipt.hash = receipt.compute_hash().unwrap_or(Hash::ZERO);
        Collapse {
            output: winner.map(|(_, o)| o),
            receipt,
        }
    }
}

/// Persist a receipt through DUCTEI. Key is `qhr/collapse/<cell>` so the
/// causal gate orders receipts per cell by `lamport`; scope is
/// `qhr.receipt` and must be on the channel's allow-list (deny-by-default
/// stays in force). Returns the envelope that was accepted.
pub fn commit(
    ch: &mut Channel,
    node: [u8; 16],
    lamport: u64,
    receipt: &CollapseReceipt,
) -> Result<Envelope, ChannelError> {
    let blob = serde_json::to_vec(receipt).map_err(|e| ChannelError::Io(e.to_string()))?;
    let key = format!("{RECEIPT_KEY_PREFIX}{}", receipt.cell);
    let mut env = ductei_core::scoped(&key, &[RECEIPT_SCOPE], node, lamport, &blob);
    env.schema_ver = RECEIPT_SCHEMA;
    ch.send(env.clone())?;
    Ok(env)
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    /// Receipt at this position fails to re-hash to its stored `hash`.
    BadHash { index: usize },
    /// Receipt's `prev` is not the previous receipt's `hash`.
    BrokenLink { index: usize },
    /// Envelope carried the qhr scope but did not parse as a receipt.
    Malformed { index: usize },
}

/// Walk accepted envelopes (from `Channel::replay`) for one cell's receipts
/// and verify the hash chain. `genesis` is the `prev` the first receipt
/// must carry (usually `Hash::ZERO`, or a chain-head anchor from a peer).
pub fn verify_chain(envs: &[Envelope], cell: &str, genesis: Hash) -> Result<usize, ChainError> {
    let key = format!("{RECEIPT_KEY_PREFIX}{cell}");
    let mut prev = genesis;
    let mut n = 0usize;
    for (i, e) in envs.iter().enumerate().filter(|(_, e)| e.key == key) {
        let r: CollapseReceipt =
            serde_json::from_slice(&e.blob).map_err(|_| ChainError::Malformed { index: i })?;
        if r.prev != prev {
            return Err(ChainError::BrokenLink { index: i });
        }
        if r.compute_hash()
            .map_err(|_| ChainError::Malformed { index: i })?
            != r.hash
        {
            return Err(ChainError::BadHash { index: i });
        }
        prev = r.hash;
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ductei_core::ScopePolicy;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Finds x such that x*x == target among candidate inputs.
    struct Sqrt;
    impl Cell for Sqrt {
        type In = (u64, u64);
        type Out = u64;
        fn name(&self) -> &'static str {
            "sqrt"
        }
        fn run(&self, _c: &Ctx, (x, _t): &Self::In) -> u64 {
            *x
        }
        fn verify(&self, (x, t): &Self::In, out: &u64) -> bool {
            out == x && x * x == *t
        }
    }

    struct Slow(Duration);
    impl Cell for Slow {
        type In = u32;
        type Out = u32;
        fn name(&self) -> &'static str {
            "slow"
        }
        fn run(&self, c: &Ctx, i: &u32) -> u32 {
            let t0 = Instant::now();
            while t0.elapsed() < self.0 {
                if c.cancelled() {
                    return u32::MAX;
                }
                std::thread::sleep(Duration::from_micros(200));
            }
            *i
        }
    }

    struct Boom;
    impl Cell for Boom {
        type In = u8;
        type Out = u8;
        fn name(&self) -> &'static str {
            "boom"
        }
        fn run(&self, _c: &Ctx, i: &u8) -> u8 {
            if *i == 1 {
                panic!("boom")
            }
            *i
        }
    }

    fn far() -> Deadline {
        Deadline::after(&MonotonicClock, Duration::from_secs(5))
    }

    #[test]
    fn first_verified_branch_wins_and_others_are_classified() {
        let s = Scheduler::default().with_fan_out(8);
        let c = s.superpose(
            &Sqrt,
            vec![(3, 49).into(), (7, 49).into(), (8, 49).into()],
            far(),
            Hash::ZERO,
        );
        assert_eq!(c.output, Some(7));
        assert_eq!(c.receipt.winner, Some(1));
        assert_eq!(c.receipt.branches[1].fate, Fate::Won);
        for i in [0, 2] {
            let b = &c.receipt.branches[i];
            assert!(
                matches!(b.fate, Fate::Rejected | Fate::Lost),
                "{:?}",
                b.fate
            );
            assert_eq!(b.out_hash.is_some(), b.fate == Fate::Rejected);
        }
        assert_eq!(c.receipt.compute_hash().unwrap(), c.receipt.hash);
    }

    #[test]
    fn no_verified_branch_means_no_output() {
        let c = Scheduler::default().superpose(&Sqrt, vec![(2, 49).into()], far(), Hash::ZERO);
        assert!(c.output.is_none());
        assert_eq!(c.receipt.winner, None);
    }

    #[test]
    fn fan_out_cap_prunes_lowest_weight() {
        let s = Scheduler::default().with_fan_out(1);
        let branches = vec![
            Branch {
                input: (3u64, 49u64),
                weight: 0.1,
            },
            Branch {
                input: (7, 49),
                weight: 0.9,
            },
        ];
        let c = s.superpose(&Sqrt, branches, far(), Hash::ZERO);
        assert_eq!(c.output, Some(7));
        assert_eq!(c.receipt.branches[0].fate, Fate::Pruned);
        assert_eq!(c.receipt.branches[0].elapsed_us, 0);
    }

    #[test]
    fn deadline_expires_slow_branches() {
        let s = Scheduler::default();
        let d = Deadline::after(&MonotonicClock, Duration::from_millis(20));
        let c = s.superpose(
            &Slow(Duration::from_millis(300)),
            vec![1.into(), 2.into()],
            d,
            Hash::ZERO,
        );
        assert!(c.output.is_none());
        for b in &c.receipt.branches {
            // Either cancelled cooperatively (returned early) and then
            // classified Expired/Cancelled, never Won.
            assert!(
                matches!(b.fate, Fate::Expired | Fate::Rejected),
                "{:?}",
                b.fate
            );
            assert_ne!(b.fate, Fate::Won);
        }
    }

    #[test]
    fn winner_cancels_slower_siblings() {
        struct Mixed(Arc<AtomicUsize>);
        impl Cell for Mixed {
            type In = u32;
            type Out = u32;
            fn name(&self) -> &'static str {
                "mixed"
            }
            fn run(&self, c: &Ctx, i: &u32) -> u32 {
                if *i == 0 {
                    return 0;
                }
                let t0 = Instant::now();
                while t0.elapsed() < Duration::from_secs(2) {
                    if c.cancelled() {
                        self.0.fetch_add(1, Ordering::SeqCst);
                        return u32::MAX;
                    }
                    std::thread::sleep(Duration::from_micros(200));
                }
                *i
            }
            fn verify(&self, _i: &u32, o: &u32) -> bool {
                *o != u32::MAX
            }
        }
        let seen = Arc::new(AtomicUsize::new(0));
        let t0 = Instant::now();
        let c = Scheduler::default().with_fan_out(4).superpose(
            &Mixed(seen.clone()),
            vec![0.into(), 1.into(), 2.into()],
            far(),
            Hash::ZERO,
        );
        assert_eq!(c.output, Some(0));
        assert!(
            t0.elapsed() < Duration::from_secs(1),
            "siblings were not cancelled promptly"
        );
        assert_eq!(seen.load(Ordering::SeqCst), 2);
    }

    fn pooled() -> Scheduler {
        Scheduler::default().with_fan_out(8).with_pool(Pool::new(4))
    }

    #[test]
    fn pool_first_verified_branch_wins() {
        let s = pooled();
        let c = s.superpose(
            &Sqrt,
            vec![(3, 49).into(), (7, 49).into(), (8, 49).into()],
            far(),
            Hash::ZERO,
        );
        assert_eq!(c.output, Some(7));
        assert_eq!(c.receipt.winner, Some(1));
        assert_eq!(c.receipt.compute_hash().unwrap(), c.receipt.hash);
    }

    #[test]
    fn pool_panic_is_contained_and_worker_survives() {
        let s = pooled();
        for _ in 0..20 {
            let c = s.superpose(&Boom, vec![1u8.into(), 2u8.into()], far(), Hash::ZERO);
            assert_eq!(c.output, Some(2));
            assert_eq!(c.receipt.branches[0].fate, Fate::Panicked);
        }
    }

    #[test]
    fn pool_deadline_expires_slow_branches() {
        let s = pooled();
        let d = Deadline::after(&MonotonicClock, Duration::from_millis(20));
        let c = s.superpose(
            &Slow(Duration::from_millis(300)),
            vec![1.into(), 2.into()],
            d,
            Hash::ZERO,
        );
        assert!(c.output.is_none());
        for b in &c.receipt.branches {
            assert!(
                matches!(b.fate, Fate::Expired | Fate::Rejected),
                "{:?}",
                b.fate
            );
        }
    }

    #[test]
    fn pool_winner_cancels_siblings_promptly() {
        struct Mixed;
        impl Cell for Mixed {
            type In = u32;
            type Out = u32;
            fn name(&self) -> &'static str {
                "mixed"
            }
            fn run(&self, c: &Ctx, i: &u32) -> u32 {
                if *i == 0 {
                    return 0;
                }
                let t0 = Instant::now();
                while t0.elapsed() < Duration::from_secs(2) {
                    if c.cancelled() {
                        return u32::MAX;
                    }
                    std::thread::sleep(Duration::from_micros(200));
                }
                *i
            }
            fn verify(&self, _i: &u32, o: &u32) -> bool {
                *o != u32::MAX
            }
        }
        let t0 = Instant::now();
        let c = pooled().superpose(
            &Mixed,
            vec![0.into(), 1.into(), 2.into()],
            far(),
            Hash::ZERO,
        );
        assert_eq!(c.output, Some(0));
        assert!(t0.elapsed() < Duration::from_secs(1));
    }

    /// Soundness of the lifetime erasure: inputs live on this stack frame
    /// and are dropped right after each collapse, while the pool outlives
    /// all of them. Every branch output must still be derived from its own
    /// input, across many collapses sharing the same workers.
    #[test]
    fn pool_borrows_never_outlive_the_collapse() {
        struct Echo;
        impl Cell for Echo {
            type In = String;
            type Out = String;
            fn name(&self) -> &'static str {
                "echo"
            }
            fn run(&self, _c: &Ctx, i: &String) -> String {
                format!("{i}!")
            }
            fn verify(&self, i: &String, o: &String) -> bool {
                o.len() == i.len() + 1 && i.ends_with('7')
            }
        }
        let pool = Pool::new(3);
        let s = Scheduler::default()
            .with_fan_out(8)
            .with_pool(Arc::clone(&pool));
        let mut prev = Hash::ZERO;
        for round in 0..500u32 {
            let inputs: Vec<Branch<String>> =
                (0..8).map(|k| format!("r{round}-k{k}").into()).collect();
            let c = s.superpose(&Echo, inputs, far(), prev);
            assert_eq!(c.output, Some(format!("r{round}-k7!")));
            assert_eq!(c.receipt.winner, Some(7));
            prev = c.receipt.hash;
        }
    }

    #[test]
    fn panic_in_a_branch_is_contained() {
        let c =
            Scheduler::default().superpose(&Boom, vec![1u8.into(), 2u8.into()], far(), Hash::ZERO);
        assert_eq!(c.output, Some(2));
        assert_eq!(c.receipt.branches[0].fate, Fate::Panicked);
    }

    #[test]
    fn budget_overrun_is_recorded() {
        let c = Scheduler::default().superpose(
            &Slow(Duration::from_millis(5)),
            vec![1.into()],
            far(),
            Hash::ZERO,
        );
        assert_eq!(c.output, Some(1));
        assert!(c.receipt.branches[0].over_budget);
        assert_eq!(c.receipt.budget_us, 1000);
    }

    #[test]
    fn receipts_commit_through_ductei_and_chain_verifies() {
        let dir = std::env::temp_dir().join(format!("qhr-sched-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("accepted.jsonl");
        let rej = dir.join("rejected.jsonl");
        let _ = std::fs::remove_file(&log);
        let _ = std::fs::remove_file(&rej);

        let policy = ScopePolicy::new().allow(RECEIPT_SCOPE);
        let mut ch = Channel::open(policy, &log, &rej).unwrap();
        let node = [7u8; 16];
        let s = Scheduler::default();

        let mut prev = Hash::ZERO;
        for (lamport, t) in [(1u64, 49u64), (2, 64), (3, 81)] {
            let c = s.superpose(
                &Sqrt,
                vec![(7, t).into(), (8, t).into(), (9, t).into()],
                far(),
                prev,
            );
            assert!(c.output.is_some());
            commit(&mut ch, node, lamport, &c.receipt).unwrap();
            prev = c.receipt.hash;
        }

        // Deny-by-default: a channel without the scope refuses receipts.
        let mut closed = Channel::open(
            ScopePolicy::new(),
            dir.join("c.jsonl"),
            dir.join("cr.jsonl"),
        )
        .unwrap();
        let c = s.superpose(&Sqrt, vec![(7, 49).into()], far(), Hash::ZERO);
        assert!(matches!(
            commit(&mut closed, node, 1, &c.receipt),
            Err(ChannelError::ScopeDenied(_))
        ));

        // Causal gate: a replayed lamport is stale, not re-appended.
        assert!(matches!(
            commit(&mut ch, node, 2, &c.receipt),
            Err(ChannelError::StaleDelta { .. })
        ));

        let (envs, _) = ch.replay(0).unwrap();
        assert_eq!(verify_chain(&envs, "sqrt", Hash::ZERO), Ok(3));
        assert_eq!(
            verify_chain(&envs, "sqrt", Hash::of(b"wrong")),
            Err(ChainError::BrokenLink { index: 0 })
        );

        // Tamper: flip a byte in the second receipt's blob.
        let mut tampered = envs.clone();
        let mut r: CollapseReceipt = serde_json::from_slice(&tampered[1].blob).unwrap();
        r.winner = Some(99);
        tampered[1].blob = serde_json::to_vec(&r).unwrap();
        assert_eq!(
            verify_chain(&tampered, "sqrt", Hash::ZERO),
            Err(ChainError::BadHash { index: 1 })
        );

        // Restart: a reopened channel rebuilds gate state from the log.
        drop(ch);
        let mut ch2 = Channel::open(ScopePolicy::new().allow(RECEIPT_SCOPE), &log, &rej).unwrap();
        assert!(matches!(
            commit(&mut ch2, node, 3, &c.receipt),
            Err(ChannelError::StaleDelta { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
