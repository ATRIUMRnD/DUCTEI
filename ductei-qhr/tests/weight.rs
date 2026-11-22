//! Lane weighting: candidate scan, evidence weights, J-lens flag, receipts.

use ductei_mcp::{Durability, SignCfg};
use ductei_qhr::lanes::CpuLane;
use ductei_qhr::weight::{argmax, EvidenceWeighter, JLens, Uniform};
use ductei_qhr::{Assurance, Evidence, Health, Job, Lane, LaneId, Qhr, Status, Weighter};
use ductei_router::{Kind, Task};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("qhrw-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn open(d: &std::path::Path) -> Qhr {
    Qhr::open(d, &SignCfg::default(), Durability { sync_every: 100, sync_max_ms: 0, background: false }).unwrap()
}

fn job(id: &str, op: &str, budget_ms: u64) -> Job {
    let task = Task { id: id.into(), intent: "test".into(), kind: Kind::Classify, criticality: 0, private: true, effects: vec![] };
    Job { task, op: op.into(), payload: "x".into(), budget_ms, assurance: Assurance::Verified }
}

/// Accepts any op; counts runs; fails every run when `fail` is set.
struct Any { id: LaneId, runs: Arc<AtomicUsize>, delay: Duration, fail: bool }
impl Lane for Any {
    fn id(&self) -> LaneId { self.id }
    fn health(&self) -> Health { Health::Ready }
    fn run(&self, _: &Job, _: Instant) -> Result<String, String> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        if self.fail { Err("boom".into()) } else { Ok("ok".into()) }
    }
}

fn any(id: LaneId, delay_ms: u64, fail: bool) -> (Arc<Any>, Arc<AtomicUsize>) {
    let runs = Arc::new(AtomicUsize::new(0));
    (Arc::new(Any { id, runs: runs.clone(), delay: Duration::from_millis(delay_ms), fail }), runs)
}

#[test]
fn argmax_prefers_highest_then_earliest_and_ignores_zero_nan() {
    assert_eq!(argmax(&[]), None);
    assert_eq!(argmax(&[(LaneId::Cpu, 0.0), (LaneId::Llm, f64::NAN)]), None);
    assert_eq!(argmax(&[(LaneId::Cpu, 1.0), (LaneId::Cuda, 1.0)]), Some(0));
    assert_eq!(argmax(&[(LaneId::Cpu, 0.2), (LaneId::Cuda, 0.9), (LaneId::Llm, 0.9)]), Some(1));
    assert_eq!(argmax(&[(LaneId::Cpu, -3.0), (LaneId::Cuda, 0.1)]), Some(1));
}

#[test]
fn uniform_matches_prefix_picker_on_prefixed_ops() {
    let d = dir("uniform");
    let mut q = open(&d);
    q.register(Arc::new(CpuLane));
    let (l, llm_runs) = any(LaneId::Llm, 0, false);
    q.register(l);
    let r = q.submit(&job("a", "cpu.echo", 1000), &[]).unwrap();
    assert_eq!(r.lane, Some(LaneId::Cpu));
    assert!(r.pick_why.starts_with("uniform:cpu<-[cpu=1.000]"), "{}", r.pick_why);
    assert_eq!(llm_runs.load(Ordering::SeqCst), 0);
    // Unprefixed op with Uniform: CPU wins the tie, as the old `_ => Cpu` arm did.
    // CpuLane rejects the op in pre-flight, so the only survivor is the Llm lane here.
    let r = q.submit(&job("b", "whatever", 1000), &[]).unwrap();
    assert_eq!(r.lane, Some(LaneId::Llm));
    assert!(r.pick_why.contains("llm=1.000") && !r.pick_why.contains("cpu="), "{}", r.pick_why);
}

#[test]
fn unprefixed_op_with_no_taker_is_refused_with_every_reason() {
    let d = dir("notaker");
    let mut q = open(&d);
    q.register(Arc::new(CpuLane));
    let r = q.submit(&job("a", "nobody.home", 1000), &[]).unwrap();
    assert_eq!(r.lane, None);
    assert!(matches!(&r.status, Status::Refused(w) if w.contains("no lane accepted") && w.contains("cpu:") && w.contains("cuda:")), "{:?}", r.status);
}

#[test]
fn evidence_weighter_moves_work_off_a_failing_lane() {
    let d = dir("evidence");
    let mut q = open(&d);
    q.set_weighter(Box::new(EvidenceWeighter));
    let (bad, bad_runs) = any(LaneId::Cpu, 0, true);
    let (good, good_runs) = any(LaneId::Cuda, 0, false);
    q.register(bad);
    q.register(good);
    // Both start at the same prior; CPU wins the tie and fails. From the second job on, CUDA leads.
    let r0 = q.submit(&job("0", "work", 1000), &[]).unwrap();
    assert_eq!(r0.lane, Some(LaneId::Cpu));
    assert!(matches!(r0.status, Status::LaneError(_)));
    for i in 1..6 { q.submit(&job(&i.to_string(), "work", 1000), &[]).unwrap(); }
    assert_eq!(bad_runs.load(Ordering::SeqCst), 1, "failing lane kept getting work");
    assert_eq!(good_runs.load(Ordering::SeqCst), 5);
    assert_eq!(q.kind_runs(LaneId::Cpu, Kind::Classify), (0, 1));
    assert_eq!(q.kind_runs(LaneId::Cuda, Kind::Classify), (5, 5));
}

#[test]
fn evidence_headroom_uses_p50_only_after_enough_samples() {
    let w = EvidenceWeighter;
    let j = job("x", "work", 10);
    let fresh = Evidence { latency_us: None, kind_runs: (0, 0), budget_us: 10_000 };
    assert!((w.weight(LaneId::Cpu, &j, &fresh) - 0.25).abs() < 1e-9); // 0.5 prior * 0.5 headroom
    let few = Evidence { latency_us: Some((9_000, 9_900, 5)), kind_runs: (5, 5), budget_us: 10_000 };
    let many = Evidence { latency_us: Some((9_000, 9_900, 50)), kind_runs: (5, 5), budget_us: 10_000 };
    assert!(w.weight(LaneId::Cpu, &j, &few) > w.weight(LaneId::Cpu, &j, &many), "p50 near budget must cost weight once trusted");
    let roomy = Evidence { latency_us: Some((100, 200, 50)), kind_runs: (5, 5), budget_us: 10_000 };
    assert!(w.weight(LaneId::Cpu, &j, &roomy) > w.weight(LaneId::Cpu, &j, &many));
}

#[test]
fn jlens_is_inert_until_enabled_and_abstains_cleanly() {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let oracle: ductei_qhr::weight::Oracle = Arc::new(move |id, _j, _e| { c.fetch_add(1, Ordering::SeqCst); if id == LaneId::Cuda { Some(9.0) } else { None } });
    let j = job("x", "work", 10);
    let ev = Evidence { latency_us: None, kind_runs: (0, 0), budget_us: 10_000 };

    let off = JLens::new(Box::new(Uniform), Some(oracle.clone()), false);
    assert_eq!(off.name(), "jlens:off");
    assert_eq!(off.weight(LaneId::Cuda, &j, &ev), 1.0);
    assert_eq!(calls.load(Ordering::SeqCst), 0, "disabled oracle must never be consulted");

    let on = JLens::new(Box::new(Uniform), Some(oracle), true);
    assert_eq!(on.name(), "jlens");
    assert_eq!(on.weight(LaneId::Cuda, &j, &ev), 9.0);
    assert_eq!(on.weight(LaneId::Cpu, &j, &ev), 1.0, "abstain falls through to the inner weighter");

    let no_oracle = JLens::new(Box::new(Uniform), None, true);
    assert_eq!(no_oracle.name(), "jlens:off");
}

#[test]
fn pick_why_is_bound_into_the_receipt() {
    let d = dir("receipt");
    let mut q = open(&d);
    q.register(Arc::new(CpuLane));
    let r = q.submit(&job("a", "cpu.echo", 1000), &[]).unwrap();
    assert!(!r.pick_why.is_empty());
    // Same job, same outcome, different pick_why must hash differently: the
    // result hash covers (id, tier, lane, status, pick_why).
    let a = ductei_router::sha256_json(&(&r.task_id, r.tier, r.lane, &r.status, &r.pick_why));
    let b = ductei_router::sha256_json(&(&r.task_id, r.tier, r.lane, &r.status, &"forged".to_string()));
    assert_ne!(a, b);
    let rep = ductei_qhr::verify(&d.join("verified"), &ductei_mcp::VerifyTrust::default()).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
}
