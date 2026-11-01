//! QPU lane against a fake limend (spool consumer thread) and, when asked,
//! against the real one (`--ignored`, needs D:\LIMEN\.venv).

use ductei_mcp::{Durability, SignCfg};
use ductei_qhr::qpu::{QpuConfig, QpuLane};
use ductei_qhr::{Assurance, Job, LaneId, Qhr, Status};
use ductei_router::{Kind, Task, Tier};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SMOKE_QUBO: &str = r#"{"qubo":[[["hub","leaf0"],2.0],[["leaf0","leaf0"],-1.0],[["hub","leaf1"],2.0],[["leaf1","leaf1"],-1.0],[["hub","hub"],-1.0]],"credit_budget":0.0,"fidelity_target":0.9,"offline":true}"#;

fn dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("qpu-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    for sub in ["state", "spool/pending", "spool/certs", "spool/failed", "spool/done"] { std::fs::create_dir_all(d.join(sub)).unwrap(); }
    d
}

fn open(d: &Path, cfg: QpuConfig) -> Qhr {
    let mut q = Qhr::open(&d.join("state"), &SignCfg::default(), Durability::default()).unwrap();
    q.register(Arc::new(QpuLane::new(cfg)));
    q
}

fn qjob(id: &str, payload: &str, budget_ms: u64) -> Job {
    Job { task: Task { id: id.into(), intent: "qubo".into(), kind: Kind::Quantum, criticality: 1, private: false, effects: vec![] },
          op: "qpu.run".into(), payload: payload.into(), budget_ms, assurance: Assurance::Verified }
}

/// Pretends to be limend: after `delay`, turns each pending request into a cert or a failure.
fn fake_limend(spool: PathBuf, delay: Duration, fail_with: Option<&'static str>, stop_after: Duration) {
    std::thread::spawn(move || {
        let t = Instant::now();
        while t.elapsed() < stop_after {
            for e in std::fs::read_dir(spool.join("pending")).unwrap().filter_map(Result::ok) {
                let p = e.path();
                if p.extension().is_none_or(|x| x != "json") { continue; }
                std::thread::sleep(delay);
                let id = p.file_stem().unwrap().to_string_lossy().to_string();
                let out = match fail_with {
                    None => (spool.join("certs").join(format!("{id}.json")),
                             format!(r#"{{"job_id":"{id}","backend":"statevector","tier":0,"success_probability":0.178,"fidelity_estimate":0.178,"fidelity_target":0.9,"target_met":false,"lamport":1}}"#)),
                    Some(why) => (spool.join("failed").join(format!("{id}.json")),
                                  format!(r#"{{"job_id":"{id}","error":"{why}"}}"#)),
                };
                if std::fs::rename(&p, spool.join("done").join(format!("{id}.json"))).is_ok() { std::fs::write(out.0, out.1).unwrap(); }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
}

#[test]
fn qubo_job_round_trips_through_limend_spool_contract() {
    let d = dir("ok");
    fake_limend(d.join("spool"), Duration::from_millis(20), None, Duration::from_secs(5));
    let mut cfg = QpuConfig::new(d.join("spool")); cfg.est_job_secs = 0;
    let mut q = open(&d, cfg);
    let r = q.submit(&qjob("q1", SMOKE_QUBO, 3_000), &[]).unwrap();
    assert_eq!((r.tier, r.lane), (Tier::TQuantum, Some(LaneId::Qpu)));
    let Status::Done(out) = &r.status else { panic!("{:?}", r.status) };
    let v: serde_json::Value = serde_json::from_str(out).unwrap();
    assert_eq!(v["backend"], "statevector");
    assert_eq!(v["target_met"], false);
    assert!(v.get("fidelity_estimate").is_none(), "closed type: only CertSummary fields come back");
    assert!(d.join("spool/done/q1.json").exists());
    assert_eq!(q.receipts(Assurance::Verified).seq, 1);
}

#[test]
fn limend_failure_is_a_lane_error_with_its_reason() {
    let d = dir("fail");
    fake_limend(d.join("spool"), Duration::ZERO, Some("ValueError: nope"), Duration::from_secs(5));
    let mut cfg = QpuConfig::new(d.join("spool")); cfg.est_job_secs = 0;
    let mut q = open(&d, cfg);
    let r = q.submit(&qjob("q2", SMOKE_QUBO, 3_000), &[]).unwrap();
    assert!(matches!(&r.status, Status::LaneError(e) if e.contains("ValueError: nope")), "{:?}", r.status);
}

#[test]
fn deadline_withdraws_an_untaken_request() {
    let d = dir("withdraw");
    // No limend at all.
    let mut cfg = QpuConfig::new(d.join("spool")); cfg.est_job_secs = 0; cfg.poll = Duration::from_millis(5);
    let mut q = open(&d, cfg);
    let r = q.submit(&qjob("q3", SMOKE_QUBO, 60), &[]).unwrap();
    // Two honest outcomes race: the runtime's timer fires (DeadlineMissed), or the
    // lane notices its own deadline first and reports the withdrawal (LaneError).
    assert!(matches!(&r.status, Status::DeadlineMissed { budget_ms: 60 } | Status::LaneError(_)), "{:?}", r.status);
    if let Status::LaneError(e) = &r.status { assert!(e.contains("withdrawn"), "{e}"); }
    // If the runtime won the race the lane is still finishing its withdrawal.
    std::thread::sleep(Duration::from_millis(80));
    assert!(!d.join("spool/pending/q3.json").exists(), "missed job must not stay queued for limend");
}

#[test]
fn preflight_refuses_bad_requests_backlog_and_queue_estimate_without_spooling() {
    let d = dir("preflight");
    // SMOKE_QUBO has 3 variables (hub, leaf0, leaf1); a ceiling of 2 must refuse it.
    let mut cfg = QpuConfig::new(d.join("spool")); cfg.max_vars = 2; cfg.max_backlog = 2; cfg.est_job_secs = 10;
    let mut q = open(&d, cfg);
    let refused = |q: &mut Qhr, id: &str, payload: &str, budget: u64| -> String {
        match q.submit(&qjob(id, payload, budget), &[]).unwrap().status { Status::Refused(w) => w, s => panic!("{s:?}") }
    };
    assert!(refused(&mut q, "a", "{not json", 60_000).contains("not a limend request"));
    assert!(refused(&mut q, "b", r#"{"qubo":[],"fidelity_target":0.9,"credit_budget":0}"#, 60_000).contains("empty"));
    assert!(refused(&mut q, "c", r#"{"qubo":[[["a","b"],1.0]],"fidelity_target":1.5,"credit_budget":0}"#, 60_000).contains("fidelity_target"));
    assert!(refused(&mut q, "d", r#"{"qubo":[[["a","b"],1.0]],"fidelity_target":0.9,"credit_budget":0,"typo":1}"#, 60_000).contains("unknown field"));
    assert!(refused(&mut q, "e", SMOKE_QUBO, 60_000).contains("exceeds the lane ceiling"), "3 vars > max 2");
    // Queue estimate: 0 ahead, 10 s each = 10 000 ms > 5 000 budget.
    let ok3 = r#"{"qubo":[[["a","b"],1.0]],"fidelity_target":0.9,"credit_budget":0}"#;
    assert!(refused(&mut q, "f", ok3, 5_000).starts_with("queue estimate"));
    // Backlog: two stale requests already pending -> lane unavailable.
    std::fs::write(d.join("spool/pending/x.json"), "{}").unwrap();
    std::fs::write(d.join("spool/pending/y.json"), "{}").unwrap();
    assert!(refused(&mut q, "g", ok3, 60_000).contains("limend is down or behind"));
    assert_eq!(std::fs::read_dir(d.join("spool/pending")).unwrap().count(), 2, "refusals never spool");
    assert_eq!(q.receipts(Assurance::Verified).seq, 7, "every refusal is receipted");
}

/// Real limend, offline statevector tier, on the smoke QUBO. Needs the LIMEN venv.
/// cargo test -p ductei-qhr --test qpu -- --ignored --nocapture real_limend
#[test]
#[ignore]
fn real_limend_once_certifies_a_spooled_job() {
    let py = Path::new(r"D:\LIMEN\.venv\Scripts\python.exe");
    assert!(py.exists(), "LIMEN venv not found");
    let d = dir("real");
    let spool = d.join("spool");
    let s = spool.clone();
    // Run limend --once after the request lands (it exits when pending is empty).
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        let out = std::process::Command::new(py).args(["-m", "limen.limend", s.to_str().unwrap(), "--once", "--results-dir"])
            .arg(s.join("results")).current_dir(r"D:\LIMEN").output().expect("spawn limend");
        println!("limend exit {:?}\n{}", out.status.code(), String::from_utf8_lossy(&out.stderr));
    });
    let mut cfg = QpuConfig::new(&spool); cfg.est_job_secs = 0;
    let mut q = open(&d, cfg);
    let t = Instant::now();
    let r = q.submit(&qjob("real-1", SMOKE_QUBO, 120_000), &[]).unwrap();
    println!("status {:?} in {:?}", r.status, t.elapsed());
    let Status::Done(out) = &r.status else { panic!("{:?}", r.status) };
    let v: serde_json::Value = serde_json::from_str(out).unwrap();
    assert_eq!(v["backend"], "statevector");
    assert!(v["success_probability"].as_f64().unwrap() > 0.0);
}
