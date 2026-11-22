//! QHR end-to-end tests. Scratch dirs live under CARGO_TARGET_TMPDIR (inside
//! the target dir), never the system temp dir.

use ductei_mcp::{Durability, ReceiptLog, SignCfg};
use ductei_qhr::lanes::{CpuLane, LlmLane, UnavailableLane};
use ductei_qhr::{Assurance, Health, Job, Lane, LaneId, Qhr, Status};
use ductei_router::brain::Brain;
use ductei_router::{Effect, Kind, Task, Tier};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("qhr-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn open(d: &std::path::Path) -> Qhr {
    let mut q = Qhr::open(d, &SignCfg::default(), Durability { sync_every: 100, sync_max_ms: 0, background: false }).unwrap();
    q.register(Arc::new(CpuLane));
    q
}

fn task(id: &str, kind: Kind, private: bool, effects: Vec<Effect>) -> Task {
    Task { id: id.into(), intent: "test".into(), kind, criticality: 0, private, effects }
}

fn job(id: &str, op: &str, payload: &str, budget_ms: u64) -> Job {
    Job { task: task(id, Kind::Classify, true, vec![]), op: op.into(), payload: payload.into(), budget_ms, assurance: Assurance::Verified }
}

/// Counts runs; optional fixed delay. Lets tests prove a lane never ran.
struct Counting { id: LaneId, runs: Arc<AtomicUsize>, delay: Duration }
impl Lane for Counting {
    fn id(&self) -> LaneId { self.id }
    fn health(&self) -> Health { Health::Ready }
    fn run(&self, _job: &Job, _deadline: Instant) -> Result<String, String> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        Ok("ok".into())
    }
}

#[test]
fn cpu_job_runs_and_is_receipted_before_return() {
    let d = dir("cpu");
    let mut q = open(&d);
    let r = q.submit(&job("j1", "cpu.sha256", "abc", 1000), &[]).unwrap();
    assert_eq!(r.tier, Tier::T0Local);
    assert_eq!(r.lane, Some(LaneId::Cpu));
    assert_eq!(r.status, Status::Done(ductei_mcp::sha256_hex(b"abc")));
    assert_eq!(q.receipts(Assurance::Verified).seq, 1);
    assert_eq!(q.receipts(Assurance::Verified).head, r.receipt);
    // Verified tier: already on disk, nothing pending.
    assert_eq!(q.receipts(Assurance::Verified).unsynced(), 0);
}

#[test]
fn denied_and_unapproved_jobs_never_reach_a_lane() {
    let d = dir("gate");
    let mut q = open(&d);
    let runs = Arc::new(AtomicUsize::new(0));
    q.register(Arc::new(Counting { id: LaneId::Cpu, runs: runs.clone(), delay: Duration::ZERO }));

    let mut j = job("deny", "cpu.echo", "x", 1000);
    j.task.effects = vec![Effect::Write(r"C:\Users\x\a.txt".into())];
    let r = q.submit(&j, &[]).unwrap();
    assert!(matches!(r.status, Status::Denied(_)), "{:?}", r.status);

    let mut j = job("commit", "cpu.echo", "x", 1000);
    j.task.effects = vec![Effect::Commit];
    let r = q.submit(&j, &[]).unwrap();
    assert_eq!(r.status, Status::NeedsApproval(vec!["commit".into()]));

    assert_eq!(runs.load(Ordering::SeqCst), 0);
    // Refusals are on the record too.
    assert_eq!(q.receipts(Assurance::Verified).seq, 2);
}

#[test]
fn remote_tier_is_refused_and_quantum_without_backend_is_refused_honestly() {
    let d = dir("tiers");
    let mut q = open(&d);
    q.register(Arc::new(UnavailableLane { id: LaneId::Qpu, why: "LIMEN backend not wired".into() }));

    let mut j = job("code", "cpu.echo", "x", 1000);
    j.task = task("code", Kind::Code, false, vec![]);
    let r = q.submit(&j, &[]).unwrap();
    assert_eq!(r.tier, Tier::T1Claude);
    assert!(matches!(&r.status, Status::Refused(w) if w.contains("remote")), "{:?}", r.status);

    let mut j = job("q", "qpu.run", "", 1000);
    j.task = task("q", Kind::Quantum, false, vec![]);
    let r = q.submit(&j, &[]).unwrap();
    assert_eq!((r.tier, r.lane), (Tier::TQuantum, Some(LaneId::Qpu)));
    assert!(matches!(&r.status, Status::Refused(w) if w.contains("unavailable") && w.contains("LIMEN")), "{:?}", r.status);
}

#[test]
fn deadline_miss_is_reported_and_bounded() {
    let d = dir("deadline");
    let mut q = open(&d);
    let t = Instant::now();
    // 2 s job, 30 ms budget. The verdict must land well under the 2 s job
    // (proves the runtime stopped waiting at the deadline). Wall time also
    // includes the durable receipt fsync, which can stall on a busy disk, so
    // it only has to beat the job itself.
    let r = q.submit(&job("slow", "cpu.sleep", "2000", 30), &[]).unwrap();
    assert_eq!(r.status, Status::DeadlineMissed { budget_ms: 30 });
    let decided = Duration::from_micros(r.decided_us);
    assert!(decided < Duration::from_millis(1000), "runtime must stop waiting at the deadline, decided after {decided:?}");
    assert!(t.elapsed() < Duration::from_millis(2000), "submit must not wait out the job, took {:?}", t.elapsed());
    assert_eq!(q.receipts(Assurance::Verified).seq, 1, "a miss is receipted, never silent");
}

#[test]
fn preflight_predicts_a_miss_from_measured_p99_and_does_not_run() {
    let d = dir("predict");
    let mut q = open(&d);
    let runs = Arc::new(AtomicUsize::new(0));
    q.register(Arc::new(Counting { id: LaneId::Cpu, runs: runs.clone(), delay: Duration::from_millis(5) }));
    for i in 0..ductei_qhr::MIN_SAMPLES_FOR_PREDICTION {
        let r = q.submit(&job(&format!("w{i}"), "cpu.echo", "x", 1000), &[]).unwrap();
        assert!(matches!(r.status, Status::Done(_)));
    }
    let (_, p99, n) = q.latency(LaneId::Cpu).unwrap();
    assert!(p99 >= 5_000 && n == ductei_qhr::MIN_SAMPLES_FOR_PREDICTION);
    let before = runs.load(Ordering::SeqCst);
    let r = q.submit(&job("tight", "cpu.echo", "x", 1), &[]).unwrap();
    assert!(matches!(&r.status, Status::Refused(w) if w.starts_with("predicted miss")), "{:?}", r.status);
    assert_eq!(runs.load(Ordering::SeqCst), before, "a predicted miss must not run");
}

#[test]
fn unknown_op_and_zero_budget_are_refused_in_preflight() {
    let d = dir("ops");
    let mut q = open(&d);
    assert!(matches!(q.submit(&job("a", "cpu.nope", "", 100), &[]).unwrap().status, Status::Refused(_)));
    assert!(matches!(q.submit(&job("b", "cpu.echo", "", 0), &[]).unwrap().status, Status::Refused(_)));
}

#[test]
fn fast_assurance_batches_fsync_and_flush_drains_it() {
    let d = dir("fast");
    let mut q = open(&d);
    for i in 0..10 {
        let mut j = job(&format!("f{i}"), "cpu.echo", "x", 1000);
        j.assurance = Assurance::Fast;
        q.submit(&j, &[]).unwrap();
    }
    assert_eq!(q.receipts(Assurance::Fast).seq, 10);
    assert_eq!(q.receipts(Assurance::Fast).unsynced(), 10);
    assert_eq!(q.receipts(Assurance::Verified).seq, 0, "chains are separate");
    q.flush().unwrap();
    assert_eq!(q.receipts(Assurance::Fast).unsynced(), 0);
}

#[test]
fn chains_survive_restart_and_reopen_verifies_them() {
    let d = dir("restart");
    {
        let mut q = open(&d);
        q.submit(&job("a", "cpu.echo", "1", 1000), &[]).unwrap();
        let mut j = job("b", "cpu.echo", "2", 1000);
        j.assurance = Assurance::Fast;
        q.submit(&j, &[]).unwrap();
        q.flush().unwrap();
    }
    // ReceiptLog::open refuses a damaged chain, so a clean reopen is the check.
    assert_eq!(ReceiptLog::open(&d.join("verified"), &SignCfg::default()).unwrap().seq, 1);
    assert_eq!(ReceiptLog::open(&d.join("fast"), &SignCfg::default()).unwrap().seq, 1);
    let mut q = open(&d);
    q.submit(&job("c", "cpu.echo", "3", 1000), &[]).unwrap();
    assert_eq!(q.receipts(Assurance::Verified).seq, 2);
}

#[test]
fn verify_passes_clean_chains_and_catches_tamper_and_foreign_lines() {
    use ductei_mcp::VerifyTrust;
    let d = dir("verify");
    let mut q = open(&d);
    q.submit(&job("v1", "cpu.echo", "a", 1000), &[]).unwrap();
    let mut jd = job("v2", "cpu.echo", "b", 1000); jd.task.effects = vec![Effect::Commit];
    q.submit(&jd, &[]).unwrap(); // needs_approval, receipted
    let mut jf = job("v3", "cpu.echo", "c", 1000); jf.assurance = Assurance::Fast;
    q.submit(&jf, &[]).unwrap();
    q.flush().unwrap();
    let trust = VerifyTrust { allow_unpinned: true, ..Default::default() };
    let v = ductei_qhr::verify_state(&d, "verified", &trust).unwrap();
    let f = ductei_qhr::verify_state(&d, "fast", &trust).unwrap();
    assert!(v.ok() && v.receipts == 2, "{:?}", v.errors);
    assert!(f.ok() && f.receipts == 1, "{:?}", f.errors);
    // Flip a verdict: chain hash breaks and the verdict check fires.
    let p = d.join("verified/receipts.jsonl");
    let text = std::fs::read_to_string(&p).unwrap().replacen("\"verdict\":\"needs_approval\"", "\"verdict\":\"done\"", 1);
    std::fs::write(&p, text).unwrap();
    let v = ductei_qhr::verify_state(&d, "verified", &trust).unwrap();
    assert!(!v.ok());
    // A gate receipt smuggled into a QHR chain is rejected by vocabulary even if its hash were right.
    let p = d.join("fast/receipts.jsonl");
    let mut text = std::fs::read_to_string(&p).unwrap();
    text.push_str(r#"{"v":1,"seq":1,"prev":"00","kid":"","key":"x","scope":"mcp:s:tool","verdict":"accepted","lamport_call":0,"lamport_result":0,"call_sha256":"ab","result_sha256":"cd","hash":"ef","scheme":"none","sig":null}"#);
    text.push('\n');
    std::fs::write(&p, text).unwrap();
    let f = ductei_qhr::verify_state(&d, "fast", &trust).unwrap();
    assert!(f.errors.iter().any(|e| e.contains("not a QHR verdict")) && f.errors.iter().any(|e| e.contains("not a QHR scope")), "{:?}", f.errors);
}

struct Failing;
impl Lane for Failing {
    fn id(&self) -> LaneId { LaneId::Cpu }
    fn health(&self) -> Health { Health::Ready }
    fn run(&self, _job: &Job, _deadline: Instant) -> Result<String, String> { Err("boom".into()) }
}

#[test]
fn router_escalation_still_applies_and_survives_restart() {
    let d = dir("escalate");
    {
        let mut q = open(&d);
        q.register(Arc::new(Failing));
        // Router rule: >= 3 recent outcomes on the tier and more than half failed -> escalate.
        for i in 0..4 {
            let r = q.submit(&job(&format!("x{i}"), "cpu.echo", "x", 1000), &[]).unwrap();
            if i < 3 { assert!(matches!(r.status, Status::LaneError(_)), "{i}: {:?}", r.status); }
        }
    }
    // Escalation needs a non-private task (private is pinned to T0 before the rule runs).
    let mut j = job("after", "cpu.echo", "x", 1000);
    j.task.private = false;
    let mut q = open(&d);
    let r = q.submit(&j, &[]).unwrap();
    assert_eq!(r.tier, Tier::T1Claude, "outcomes reloaded from disk must drive the same escalation");
    assert!(matches!(&r.status, Status::Refused(w) if w.contains("remote")));
}

struct Fixed;
impl Brain for Fixed {
    fn name(&self) -> String { "fixed".into() }
    fn complete(&self, _: &str, p: &str) -> Result<String, String> { Ok(format!("echo: {p}")) }
}

#[test]
fn llm_lane_runs_through_the_same_gate() {
    let d = dir("llm");
    let mut q = open(&d);
    q.register(Arc::new(LlmLane::with_brain(Box::new(Fixed))));
    let r = q.submit(&job("l", "llm.complete", "hi", 1000), &[]).unwrap();
    assert_eq!((r.lane, r.status), (Some(LaneId::Llm), Status::Done("echo: hi".into())));
    assert!(matches!(q.submit(&job("e", "llm.complete", "  ", 1000), &[]).unwrap().status, Status::Refused(_)));
}

/// Overhead of the whole pipeline (gate, route, pre-flight, thread, receipt)
/// on a trivial CPU job. Run in release:
/// cargo test -p ductei-qhr --release --test qhr -- --ignored --nocapture
#[test]
#[ignore]
fn bench_submit_overhead() {
    let pct = |mut v: Vec<u64>, f: f64| { v.sort_unstable(); v[((v.len() - 1) as f64 * f) as usize] as f64 / 1000.0 };
    // Floor: what one thread spawn + channel round-trip costs on this machine.
    let spawn: Vec<u64> = (0..2000).map(|_| {
        let t = Instant::now();
        let (tx, rx) = std::sync::mpsc::sync_channel::<u8>(1);
        std::thread::spawn(move || { let _ = tx.send(1); });
        let _ = rx.recv();
        t.elapsed().as_micros() as u64
    }).collect();
    println!("floor    thread spawn+recv   p50 {:.3} ms  p99 {:.3} ms", pct(spawn.clone(), 0.5), pct(spawn, 0.99));
    let inline = Durability { sync_every: 100, sync_max_ms: 0, background: false };
    let bg = Durability { sync_every: 1_000, sync_max_ms: 10, background: true };
    for (label, a, dur) in [("verified", Assurance::Verified, inline), ("fast-inl", Assurance::Fast, inline), ("fast-bg", Assurance::Fast, bg)] {
        let d = dir(&format!("bench-{label}"));
        let mut q = Qhr::open(&d, &SignCfg::default(), dur).unwrap();
        q.register(Arc::new(CpuLane));
        let mut us: Vec<u64> = (0..2000).map(|i| {
            let mut j = job(&format!("b{i}"), "cpu.echo", "x", 1000);
            j.assurance = a;
            q.submit(&j, &[]).unwrap().elapsed_us
        }).collect();
        q.flush().unwrap();
        us.sort_unstable();
        let p = |f: f64| us[((us.len() - 1) as f64 * f) as usize] as f64 / 1000.0;
        println!("{label:8} submit end-to-end  p50 {:.3} ms  p99 {:.3} ms  max {:.3} ms", p(0.5), p(0.99), p(1.0));
    }
}
