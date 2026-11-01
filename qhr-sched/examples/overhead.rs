//! Measures scheduler overhead: 8 trivial branches, 2000 collapses.
//! Run: cargo run --release -p qhr-sched --example overhead
use qhr_cell::{Cell, Ctx, Deadline, Hash, MonotonicClock};
use qhr_sched::{Branch, Scheduler};
use std::time::{Duration, Instant};

struct Pick;
impl Cell for Pick {
    type In = u32;
    type Out = u32;
    fn name(&self) -> &'static str {
        "pick"
    }
    fn run(&self, _c: &Ctx, i: &u32) -> u32 {
        i.wrapping_mul(2654435761)
    }
    fn verify(&self, i: &u32, _o: &u32) -> bool {
        *i == 5
    }
}

fn main() {
    let s = Scheduler::default().with_fan_out(8); // default cap is cores*2; equal weights prune by position
    let n = 2000;
    let mut prev = Hash::ZERO;
    let t0 = Instant::now();
    for _ in 0..n {
        let d = Deadline::after(&MonotonicClock, Duration::from_millis(5));
        let c = s.superpose(&Pick, (0..8u32).map(Branch::from).collect(), d, prev);
        assert_eq!(c.output, Some(5u32.wrapping_mul(2654435761)));
        prev = c.receipt.hash;
    }
    let per = t0.elapsed() / n;
    println!(
        "fan_out_cap={} collapses={} per_collapse={:?} (8 branches, spawn+hash+receipt)",
        s.fan_out_cap, n, per
    );
}
