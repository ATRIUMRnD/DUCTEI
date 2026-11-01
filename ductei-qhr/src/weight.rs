//! Lane weighting: evidence-based lane choice for QHR.
//!
//! The runtime builds the candidate set (lanes that are registered, healthy,
//! accept the op, and are not predicted to miss the budget), then asks the
//! `Weighter` for one non-negative weight per candidate and runs the highest.
//! Ties fall to `LaneId` order (Cpu < Cuda < Qpu < Llm), which is what the
//! prefix-only picker chose before weighting existed.
//!
//! Three weighters ship:
//! 0. `Uniform`: every candidate weighs 1. Identical to the pre-weighting picker.
//! 1. `Evidence`: smoothed success rate on this lane for this job kind, times
//!    latency headroom against the budget. Pure measurement, no model.
//! 2. `JLens`: an external likelihood oracle (jspace-lab readout) behind a flag.
//!    Off by default and stays off until the pre-registered validation passes;
//!    while off it defers to an inner weighter and says so in `pick_why`.

use crate::{Job, LaneId, MIN_SAMPLES_FOR_PREDICTION};
use std::sync::Arc;

/// What the runtime has measured about one candidate lane for this job.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Evidence {
    /// Run-time p50 and p99 in microseconds, and the sample count, if any runs were recorded.
    pub latency_us: Option<(u64, u64, usize)>,
    /// Runs of this job's kind on this lane: (ok, total).
    pub kind_runs: (u32, u32),
    pub budget_us: u64,
}

pub trait Weighter: Send + Sync {
    fn name(&self) -> &'static str;
    /// Non-negative. NaN or negative is treated as 0 by the runtime.
    fn weight(&self, lane: LaneId, job: &Job, ev: &Evidence) -> f64;
}

pub struct Uniform;
impl Weighter for Uniform {
    fn name(&self) -> &'static str { "uniform" }
    fn weight(&self, _: LaneId, _: &Job, _: &Evidence) -> f64 { 1.0 }
}

/// Laplace-smoothed success rate times latency headroom.
/// Headroom uses p50 once the lane has enough samples; before that it is 0.5,
/// so a new lane is neither favoured nor starved.
pub struct EvidenceWeighter;
impl Weighter for EvidenceWeighter {
    fn name(&self) -> &'static str { "evidence" }
    fn weight(&self, _: LaneId, _: &Job, ev: &Evidence) -> f64 {
        let (ok, n) = ev.kind_runs;
        let success = (ok as f64 + 1.0) / (n as f64 + 2.0);
        let headroom = match ev.latency_us {
            Some((p50, _, samples)) if samples >= MIN_SAMPLES_FOR_PREDICTION && ev.budget_us > 0 => {
                ((ev.budget_us as f64 - p50 as f64) / ev.budget_us as f64).clamp(0.05, 1.0)
            }
            _ => 0.5,
        };
        success * headroom
    }
}

/// Likelihood oracle signature: `Some(weight)` or `None` to abstain for this lane.
pub type Oracle = Arc<dyn Fn(LaneId, &Job, &Evidence) -> Option<f64> + Send + Sync>;

pub struct JLens {
    inner: Box<dyn Weighter>,
    oracle: Option<Oracle>,
    enabled: bool,
}

impl JLens {
    /// `enabled` is the validation flag. Keep it false until jspace-lab's
    /// readout PREREG passes; the runtime records which path was used.
    pub fn new(inner: Box<dyn Weighter>, oracle: Option<Oracle>, enabled: bool) -> Self { Self { inner, oracle, enabled } }
    pub fn active(&self) -> bool { self.enabled && self.oracle.is_some() }
}

impl Weighter for JLens {
    fn name(&self) -> &'static str { if self.active() { "jlens" } else { "jlens:off" } }
    fn weight(&self, lane: LaneId, job: &Job, ev: &Evidence) -> f64 {
        if let (true, Some(o)) = (self.enabled, &self.oracle) {
            if let Some(w) = o(lane, job, ev) { return w; }
        }
        self.inner.weight(lane, job, ev)
    }
}

/// Pick the highest weight; ties go to the earlier candidate. Returns the
/// index into `cands`, or None when every weight is 0 (or there are none).
pub fn argmax(cands: &[(LaneId, f64)]) -> Option<usize> {
    let mut best: Option<(usize, f64)> = None;
    for (i, (_, w)) in cands.iter().enumerate() {
        let w = if w.is_finite() && *w > 0.0 { *w } else { 0.0 };
        if w == 0.0 { continue; }
        match best { Some((_, b)) if b >= w => {}, _ => best = Some((i, w)) }
    }
    best.map(|(i, _)| i)
}
