//! Measures scheduler overhead: 8 trivial branches, 2000 collapses, in both
//! modes (scoped thread per branch vs persistent pool).
//! Run: cargo run --release -p qhr-sched --example overhead
use qhr_cell::{Cell, Ctx, Deadline, Hash, MonotonicClock};
use qhr_sched::{Branch, Pool, Scheduler};
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

fn bench(label: &str, s: &Scheduler, n: u32) {
    let mut prev = Hash::ZERO;
    let mut samples = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let d = Deadline::after(&MonotonicClock, Duration::from_millis(5));
        let t0 = Instant::now();
        let c = s.superpose(&Pick, (0..8u32).map(Branch::from).collect(), d, prev);
        samples.push(t0.elapsed());
        assert_eq!(c.output, Some(5u32.wrapping_mul(2654435761)));
        prev = c.receipt.hash;
    }
    samples.sort();
    let p = |q: f64| samples[((samples.len() - 1) as f64 * q) as usize];
    println!(
        "{label:<9} fan_out_cap={} collapses={n} p50={:?} p99={:?} max={:?} (8 branches, dispatch+hash+receipt)",
        s.fan_out_cap,
        p(0.5),
        p(0.99),
        samples[samples.len() - 1]
    );
}

fn main() {
    let n = 2000;
    // Default cap is cores*2; equal weights prune by position, so cap at 8.
    bench("scoped", &Scheduler::default().with_fan_out(8), n);
    let pool = Pool::new(8);
    let pooled = Scheduler::default().with_fan_out(8).with_pool(pool);
    // Warm the workers (first dispatch pays page-in and scheduler wake).
    bench("pool-warm", &pooled, 200);
    bench("pool", &pooled, n);
}
