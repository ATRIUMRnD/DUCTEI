//! Branch weighting: evidence-based fan-out for `superpose`.
//!
//! `Scheduler::superpose` already orders branches by `Branch::weight` and
//! prunes the lowest past `fan_out_cap`. This module decides those weights
//! instead of leaving them to the caller, and learns from every collapse.
//! Same shape as `ductei_qhr::weight` (lane level), applied one level down:
//!
//! 0. `Uniform`: every branch weighs 1, so caller order decides. Identical
//!    to calling `superpose` with `Branch::from(input)`.
//! 1. `Prior`: Laplace-smoothed win rate of this branch's *class* across
//!    past collapses. The class is whatever the caller's `classify` returns
//!    (an op kind, an input bucket, a lane). Pure measurement, no model.
//! 2. `JLens`: an external likelihood oracle behind a flag. Off by default
//!    and stays off until jspace-lab's pre-registered readout validation
//!    passes; while off it defers to an inner weighter and says so in `name`.
//!
//! Weight orders and prunes. It never changes what `Cell::verify` accepts,
//! and a weighter that returns NaN, negative or zero puts that branch last.

use crate::{
    verify_chain, Branch, ChainError, Collapse, CollapseReceipt, Fate, Scheduler,
    RECEIPT_KEY_PREFIX,
};
use ductei_core::Envelope;
use qhr_cell::{Cell, Deadline, Hash};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Branches that actually ran; Pruned and Cancelled teach nothing.
fn ran(f: Fate) -> bool {
    matches!(
        f,
        Fate::Won | Fate::Lost | Fate::Rejected | Fate::Expired | Fate::Panicked
    )
}

/// Class key for the learned prior. `u64` so callers can hash anything into it.
pub type Class = u64;

pub trait BranchWeighter<In>: Send + Sync {
    fn name(&self) -> &'static str;
    /// Non-negative. NaN, negative or non-finite is treated as 0.
    fn weight(&self, input: &In) -> f32;
    /// Called once per branch after a collapse with its recorded fate.
    /// Default: learn nothing.
    fn observe(&self, _input: &In, _fate: Fate) {}
    /// Class recorded in the receipt so a replay can rebuild learning.
    /// Default: none (receipt stays in its pre-weighting form).
    fn class(&self, _input: &In) -> Option<Class> {
        None
    }
}

pub struct Uniform;
impl<In> BranchWeighter<In> for Uniform {
    fn name(&self) -> &'static str {
        "uniform"
    }
    fn weight(&self, _: &In) -> f32 {
        1.0
    }
}

/// Per-class (won, tried) counts. `tried` counts branches that actually ran
/// (Won, Lost, Rejected, Expired, Panicked); Pruned and Cancelled branches
/// taught us nothing and are not counted.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ClassStats {
    pub won: u32,
    pub tried: u32,
}

/// Laplace-smoothed win rate per class: (won + 1) / (tried + 2).
/// An unseen class weighs 0.5, so it is neither favoured nor starved.
pub struct Prior<In> {
    classify: Box<dyn Fn(&In) -> Class + Send + Sync>,
    stats: RwLock<HashMap<Class, ClassStats>>,
}

impl<In> Prior<In> {
    pub fn new(classify: impl Fn(&In) -> Class + Send + Sync + 'static) -> Self {
        Self {
            classify: Box::new(classify),
            stats: RwLock::new(HashMap::new()),
        }
    }
    pub fn stats(&self, class: Class) -> ClassStats {
        self.stats
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&class)
            .copied()
            .unwrap_or_default()
    }
    /// Snapshot of every class, for persistence or a receipt side-channel.
    pub fn snapshot(&self) -> Vec<(Class, ClassStats)> {
        let g = self.stats.read().unwrap_or_else(|p| p.into_inner());
        let mut v: Vec<_> = g.iter().map(|(k, v)| (*k, *v)).collect();
        v.sort_by_key(|(k, _)| *k);
        v
    }
    /// Rebuild learning from DUCTEI: verify `cell`'s receipt chain in
    /// `envs` (from `Channel::replay`) first, then credit every branch that
    /// carries a class. A broken chain teaches nothing and returns the error,
    /// so tampered receipts can never steer the scheduler. Returns how many
    /// branches were learned from.
    pub fn replay(&self, envs: &[Envelope], cell: &str, genesis: Hash) -> Result<usize, ChainError> {
        verify_chain(envs, cell, genesis)?;
        let key = format!("{RECEIPT_KEY_PREFIX}{cell}");
        let mut add: HashMap<Class, ClassStats> = HashMap::new();
        let mut n = 0usize;
        for (i, e) in envs.iter().enumerate().filter(|(_, e)| e.key == key) {
            let r: CollapseReceipt =
                serde_json::from_slice(&e.blob).map_err(|_| ChainError::Malformed { index: i })?;
            for b in &r.branches {
                let (Some(c), true) = (b.class, ran(b.fate)) else { continue };
                let s = add.entry(c).or_default();
                s.tried = s.tried.saturating_add(1);
                if b.fate == Fate::Won {
                    s.won = s.won.saturating_add(1);
                }
                n += 1;
            }
        }
        let mut g = self.stats.write().unwrap_or_else(|p| p.into_inner());
        for (c, s) in add {
            let e = g.entry(c).or_default();
            e.won = e.won.saturating_add(s.won);
            e.tried = e.tried.saturating_add(s.tried);
        }
        Ok(n)
    }
    /// Seed from a previous snapshot (e.g. replayed from DUCTEI receipts).
    pub fn load(&self, rows: impl IntoIterator<Item = (Class, ClassStats)>) {
        let mut g = self.stats.write().unwrap_or_else(|p| p.into_inner());
        for (k, v) in rows {
            g.insert(k, v);
        }
    }
}

impl<In> BranchWeighter<In> for Prior<In> {
    fn name(&self) -> &'static str {
        "prior"
    }
    fn weight(&self, input: &In) -> f32 {
        let s = self.stats((self.classify)(input));
        (s.won as f32 + 1.0) / (s.tried as f32 + 2.0)
    }
    fn class(&self, input: &In) -> Option<Class> {
        Some((self.classify)(input))
    }
    fn observe(&self, input: &In, fate: Fate) {
        if !ran(fate) {
            return;
        }
        let c = (self.classify)(input);
        let mut g = self.stats.write().unwrap_or_else(|p| p.into_inner());
        let e = g.entry(c).or_default();
        e.tried = e.tried.saturating_add(1);
        if fate == Fate::Won {
            e.won = e.won.saturating_add(1);
        }
    }
}

/// Likelihood oracle: `Some(weight)` or `None` to abstain for this branch.
pub type Oracle<In> = Arc<dyn Fn(&In) -> Option<f32> + Send + Sync>;

pub struct JLens<In> {
    inner: Box<dyn BranchWeighter<In>>,
    oracle: Option<Oracle<In>>,
    enabled: bool,
}

impl<In> JLens<In> {
    /// `enabled` is the validation flag. Keep it false until
    /// `D:\jspace-lab\readout\PREREG.md` passes.
    pub fn new(inner: Box<dyn BranchWeighter<In>>, oracle: Option<Oracle<In>>, enabled: bool) -> Self {
        Self {
            inner,
            oracle,
            enabled,
        }
    }
    pub fn active(&self) -> bool {
        self.enabled && self.oracle.is_some()
    }
}

impl<In: Send + Sync> BranchWeighter<In> for JLens<In> {
    fn name(&self) -> &'static str {
        if self.active() {
            "jlens"
        } else {
            "jlens:off"
        }
    }
    fn weight(&self, input: &In) -> f32 {
        if let (true, Some(o)) = (self.enabled, &self.oracle) {
            if let Some(w) = o(input) {
                return w;
            }
        }
        self.inner.weight(input)
    }
    fn observe(&self, input: &In, fate: Fate) {
        // Learning always flows to the inner weighter so the prior is warm
        // the day the flag flips.
        self.inner.observe(input, fate)
    }
    fn class(&self, input: &In) -> Option<Class> {
        self.inner.class(input)
    }
}

fn sanitize(w: f32) -> f32 {
    if w.is_finite() && w > 0.0 {
        w
    } else {
        0.0
    }
}

impl Scheduler {
    /// Weight `inputs` with `w`, run `superpose`, then feed every branch's
    /// fate back to `w`. Equal weights keep caller order, so `Uniform` here
    /// is byte-identical in behaviour to plain `superpose`.
    pub fn superpose_weighted<C, W>(
        &self,
        cell: &C,
        inputs: Vec<C::In>,
        w: &W,
        deadline: Deadline,
        prev: Hash,
    ) -> Collapse<C::Out>
    where
        C: Cell,
        C::In: Clone,
        W: BranchWeighter<C::In> + ?Sized,
    {
        let branches: Vec<Branch<C::In>> = inputs
            .iter()
            .cloned()
            .map(|input| {
                let weight = sanitize(w.weight(&input));
                Branch { input, weight }
            })
            .collect();
        let mut c = self.superpose(cell, branches, deadline, prev);
        let mut stamped = false;
        for (r, input) in c.receipt.branches.iter_mut().zip(inputs.iter()) {
            w.observe(input, r.fate);
            r.class = w.class(input);
            stamped |= r.class.is_some();
        }
        if stamped {
            c.receipt.hash = c.receipt.compute_hash().unwrap_or(Hash::ZERO);
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qhr_cell::{Ctx, MonotonicClock};
    use std::time::Duration;

    /// Input (candidate, target); verifies when candidate*candidate == target.
    struct Sqrt;
    impl Cell for Sqrt {
        type In = (u64, u64);
        type Out = u64;
        fn name(&self) -> &'static str {
            "sqrt"
        }
        fn run(&self, _c: &Ctx, (x, _): &Self::In) -> u64 {
            *x
        }
        fn verify(&self, (x, t): &Self::In, out: &u64) -> bool {
            out == x && x * x == *t
        }
        fn budget(&self) -> Duration {
            Duration::from_millis(50)
        }
    }

    fn dl() -> Deadline {
        Deadline::after(&MonotonicClock, Duration::from_millis(500))
    }

    #[test]
    fn uniform_matches_plain_superpose_order() {
        let s = Scheduler::default().with_fan_out(1);
        let inputs = vec![(2u64, 9u64), (3, 9)];
        // Cap 1 with equal weights: only the first caller input runs.
        let c = s.superpose_weighted(&Sqrt, inputs.clone(), &Uniform, dl(), Hash::ZERO);
        assert_eq!(c.receipt.branches[1].fate, Fate::Pruned);
        assert_eq!(c.output, None);
        let plain = s.superpose(
            &Sqrt,
            inputs.into_iter().map(Branch::from).collect(),
            dl(),
            Hash::ZERO,
        );
        let f = |c: &Collapse<u64>| c.receipt.branches.iter().map(|b| b.fate).collect::<Vec<_>>();
        assert_eq!(f(&c), f(&plain));
    }

    #[test]
    fn prior_learns_and_reorders() {
        // Class = candidate value. Two collapses where 3 wins, then with cap 1
        // the prior must put 3 first even though the caller lists 2 first.
        let p = Prior::new(|(x, _): &(u64, u64)| *x);
        let s = Scheduler::default().with_fan_out(8);
        for _ in 0..2 {
            let c = s.superpose_weighted(&Sqrt, vec![(2, 9), (3, 9)], &p, dl(), Hash::ZERO);
            assert_eq!(c.output, Some(3));
        }
        assert_eq!(p.stats(3).won, 2);
        assert_eq!(p.stats(3).tried, 2);
        assert_eq!(p.stats(2).won, 0);
        assert!(p.weight(&(3, 9)) > p.weight(&(2, 9)));

        let s1 = Scheduler::default().with_fan_out(1);
        let c = s1.superpose_weighted(&Sqrt, vec![(2, 9), (3, 9)], &p, dl(), Hash::ZERO);
        assert_eq!(c.output, Some(3));
        assert_eq!(c.receipt.branches[0].fate, Fate::Pruned);
        assert_eq!(c.receipt.branches[1].fate, Fate::Won);
    }

    #[test]
    fn prior_ignores_pruned_branches() {
        let p = Prior::new(|(x, _): &(u64, u64)| *x);
        let s = Scheduler::default().with_fan_out(1);
        let _ = s.superpose_weighted(&Sqrt, vec![(3, 9), (2, 9)], &p, dl(), Hash::ZERO);
        assert_eq!(p.stats(2), ClassStats::default());
        assert_eq!(p.stats(3), ClassStats { won: 1, tried: 1 });
    }

    #[test]
    fn unseen_class_weighs_half() {
        let p = Prior::new(|(x, _): &(u64, u64)| *x);
        assert_eq!(p.weight(&(7, 0)), 0.5);
    }

    #[test]
    fn snapshot_round_trips() {
        let p = Prior::new(|(x, _): &(u64, u64)| *x);
        p.observe(&(5, 0), Fate::Won);
        p.observe(&(5, 0), Fate::Lost);
        let snap = p.snapshot();
        let q = Prior::new(|(x, _): &(u64, u64)| *x);
        q.load(snap);
        assert_eq!(q.stats(5), ClassStats { won: 1, tried: 2 });
    }

    #[test]
    fn jlens_off_defers_and_still_learns() {
        let oracle: Oracle<(u64, u64)> = Arc::new(|_| Some(0.001));
        let j = JLens::new(Box::new(Uniform), Some(oracle.clone()), false);
        assert_eq!(j.name(), "jlens:off");
        assert_eq!(j.weight(&(3, 9)), 1.0);
        let on = JLens::new(Box::new(Uniform), Some(oracle), true);
        assert_eq!(on.name(), "jlens");
        assert_eq!(on.weight(&(3, 9)), 0.001);
        // Learning reaches the inner prior even while off.
        let p = Prior::new(|(x, _): &(u64, u64)| *x);
        let j = JLens::new(Box::new(p), None, false);
        j.observe(&(3, 9), Fate::Won);
        assert!(j.weight(&(3, 9)) > 0.5);
    }

    #[test]
    fn jlens_abstain_falls_through() {
        let oracle: Oracle<(u64, u64)> = Arc::new(|(x, _)| if *x == 3 { Some(0.9) } else { None });
        let j = JLens::new(Box::new(Uniform), Some(oracle), true);
        assert_eq!(j.weight(&(3, 9)), 0.9);
        assert_eq!(j.weight(&(2, 9)), 1.0);
    }

    #[test]
    fn bad_weights_go_last_not_crash() {
        struct Nan;
        impl BranchWeighter<(u64, u64)> for Nan {
            fn name(&self) -> &'static str {
                "nan"
            }
            fn weight(&self, (x, _): &(u64, u64)) -> f32 {
                if *x == 3 {
                    f32::NAN
                } else {
                    -1.0
                }
            }
        }
        let s = Scheduler::default().with_fan_out(8);
        let c = s.superpose_weighted(&Sqrt, vec![(3, 9), (2, 9)], &Nan, dl(), Hash::ZERO);
        assert!(c.receipt.branches.iter().all(|b| b.weight == 0.0));
        assert_eq!(c.output, Some(3));
    }

    #[test]
    fn weighted_receipt_hash_verifies() {
        let p = Prior::new(|(x, _): &(u64, u64)| *x);
        let s = Scheduler::default().with_fan_out(4);
        let c = s.superpose_weighted(&Sqrt, vec![(2, 9), (3, 9)], &p, dl(), Hash::ZERO);
        assert_eq!(c.receipt.compute_hash().unwrap(), c.receipt.hash);
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;
    use crate::{commit, RECEIPT_SCOPE};
    use ductei_core::{Channel, ScopePolicy};
    use qhr_cell::{Ctx, MonotonicClock};
    use std::time::Duration;

    struct Sqrt;
    impl Cell for Sqrt {
        type In = (u64, u64);
        type Out = u64;
        fn name(&self) -> &'static str {
            "sqrt"
        }
        fn run(&self, _c: &Ctx, (x, _): &Self::In) -> u64 {
            *x
        }
        fn verify(&self, (x, t): &Self::In, out: &u64) -> bool {
            out == x && x * x == *t
        }
        fn budget(&self) -> Duration {
            Duration::from_millis(50)
        }
    }

    fn dl() -> Deadline {
        Deadline::after(&MonotonicClock, Duration::from_millis(500))
    }

    fn channel(tag: &str) -> Channel {
        let dir = std::env::temp_dir().join(format!("qhr-weight-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("accepted.jsonl");
        let rej = dir.join("rejected.jsonl");
        let _ = std::fs::remove_file(&log);
        let _ = std::fs::remove_file(&rej);
        Channel::open(ScopePolicy::new().allow(RECEIPT_SCOPE), &log, &rej).unwrap()
    }

    fn by_candidate() -> Prior<(u64, u64)> {
        Prior::new(|(x, _): &(u64, u64)| *x)
    }

    /// Three collapses where 9 always wins, committed through DUCTEI.
    fn run_three(ch: &mut Channel, p: &Prior<(u64, u64)>) {
        let s = Scheduler::default().with_fan_out(8);
        let mut prev = Hash::ZERO;
        for lamport in 1..=3u64 {
            let c = s.superpose_weighted(&Sqrt, vec![(7, 81), (8, 81), (9, 81)], p, dl(), prev);
            assert_eq!(c.output, Some(9));
            commit(ch, [3u8; 16], lamport, &c.receipt).unwrap();
            prev = c.receipt.hash;
        }
    }

    #[test]
    fn cold_restart_rebuilds_prior_from_receipts() {
        let mut ch = channel("cold");
        let live = by_candidate();
        run_three(&mut ch, &live);

        // "Restart": a fresh prior learns only from the DUCTEI log.
        let (envs, _) = ch.replay(0).unwrap();
        let cold = by_candidate();
        let n = cold.replay(&envs, "sqrt", Hash::ZERO).unwrap();
        assert!(n >= 3, "learned from {n} branches");
        assert_eq!(cold.stats(9).won, 3);
        assert_eq!(cold.stats(9), live.stats(9));
        assert_eq!(cold.snapshot(), live.snapshot());
        assert!(cold.weight(&(9, 81)) > cold.weight(&(7, 81)));
    }

    #[test]
    fn tampered_receipt_teaches_nothing() {
        let mut ch = channel("tamper");
        run_three(&mut ch, &by_candidate());
        let (mut envs, _) = ch.replay(0).unwrap();
        // Flip one branch's fate in the stored blob without fixing the hash.
        let s = String::from_utf8(envs[0].blob.clone()).unwrap();
        assert!(s.contains("\"Won\""));
        envs[0].blob = s.replacen("\"Won\"", "\"Rejected\"", 1).into_bytes();

        let p = by_candidate();
        assert!(matches!(
            p.replay(&envs, "sqrt", Hash::ZERO),
            Err(ChainError::BadHash { .. })
        ));
        assert!(p.snapshot().is_empty());
    }

    #[test]
    fn wrong_genesis_teaches_nothing() {
        let mut ch = channel("genesis");
        run_three(&mut ch, &by_candidate());
        let (envs, _) = ch.replay(0).unwrap();
        let p = by_candidate();
        let bogus = Hash([1u8; 32]);
        assert!(matches!(
            p.replay(&envs, "sqrt", bogus),
            Err(ChainError::BrokenLink { .. })
        ));
        assert!(p.snapshot().is_empty());
    }

    #[test]
    fn classless_receipts_keep_pre_weighting_form() {
        // Uniform stamps no class: serialized receipt has no "class" key,
        // so receipts and hashes from before this change are unaffected.
        let s = Scheduler::default().with_fan_out(4);
        let c = s.superpose_weighted(&Sqrt, vec![(2, 4), (3, 4)], &Uniform, dl(), Hash::ZERO);
        let json = serde_json::to_string(&c.receipt).unwrap();
        assert!(!json.contains("\"class\""));
        assert_eq!(c.receipt.compute_hash().unwrap(), c.receipt.hash);
        // And a replay over classless receipts learns nothing, without error.
        let mut ch = channel("classless");
        commit(&mut ch, [3u8; 16], 1, &c.receipt).unwrap();
        let (envs, _) = ch.replay(0).unwrap();
        let p = by_candidate();
        assert_eq!(p.replay(&envs, "sqrt", Hash::ZERO), Ok(0));
    }

    #[test]
    fn stamped_receipt_round_trips_with_class() {
        let p = by_candidate();
        let s = Scheduler::default().with_fan_out(4);
        let c = s.superpose_weighted(&Sqrt, vec![(2, 4), (3, 4)], &p, dl(), Hash::ZERO);
        assert!(c.receipt.branches.iter().all(|b| b.class.is_some()));
        let back: CollapseReceipt =
            serde_json::from_str(&serde_json::to_string(&c.receipt).unwrap()).unwrap();
        assert_eq!(back.compute_hash().unwrap(), c.receipt.hash);
        assert_eq!(back.branches[1].class, Some(3));
    }
}
