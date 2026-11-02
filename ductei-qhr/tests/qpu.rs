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

// ---- ahead-of-clock cache and exact check ----

fn done_count(d: &Path) -> usize { std::fs::read_dir(d.join("spool/done")).unwrap().count() }

fn done_json(r: &ductei_qhr::Report) -> serde_json::Value {
    let Status::Done(out) = &r.status else { panic!("{:?}", r.status) };
    serde_json::from_str(out).unwrap()
}

#[test]
fn exact_check_and_shots_to_optimum_ride_along() {
    let d = dir("exact");
    fake_limend(d.join("spool"), Duration::ZERO, None, Duration::from_secs(5));
    let mut cfg = QpuConfig::new(d.join("spool")); cfg.est_job_secs = 0;
    let mut q = open(&d, cfg);
    let v = done_json(&q.submit(&qjob("x1", SMOKE_QUBO, 3_000), &[]).unwrap());
    // hub=0, leaf0=leaf1=1: -1 -1 = -2 (setting hub costs -1 but +2 per active leaf pair).
    assert_eq!(v["exact_energy"], -2.0);
    assert_eq!(v["exact_assignment"]["hub"], 0);
    assert_eq!(v["exact_assignment"]["leaf0"], 1);
    // p = 0.178: ceil(ln 0.01 / ln 0.822) = 24.
    assert_eq!(v["shots_to_optimum_99"], 24);
    assert!(v.get("cached").is_none());
}

#[test]
fn repeat_offline_request_is_served_from_cache_without_spooling() {
    let d = dir("cache");
    fake_limend(d.join("spool"), Duration::from_millis(20), None, Duration::from_secs(5));
    let mut cfg = QpuConfig::new(d.join("spool")); cfg.est_job_secs = 0;
    let mut q = open(&d, cfg);
    let first = done_json(&q.submit(&qjob("c1", SMOKE_QUBO, 3_000), &[]).unwrap());
    assert!(first.get("cached").is_none());
    let t = Instant::now();
    let r2 = q.submit(&qjob("c2", SMOKE_QUBO, 3_000), &[]).unwrap();
    let hit = t.elapsed();
    let second = done_json(&r2);
    assert_eq!(second["cached"], true);
    assert_eq!(second["job_id"], "c1", "a hit names the run that produced it");
    assert_eq!(second["success_probability"], first["success_probability"]);
    assert_eq!(done_count(&d), 1, "the repeat never reached limend");
    assert!(hit < Duration::from_millis(15), "cache hit took {hit:?}");
    assert_eq!(q.receipts(Assurance::Verified).seq, 2, "a hit is still receipted");
}

#[test]
fn cached_answers_still_serve_while_limend_is_down() {
    let d = dir("cache-down");
    fake_limend(d.join("spool"), Duration::ZERO, None, Duration::from_secs(5));
    let mut cfg = QpuConfig::new(d.join("spool")); cfg.est_job_secs = 0; cfg.max_backlog = 2;
    let mut q = open(&d, cfg);
    done_json(&q.submit(&qjob("w1", SMOKE_QUBO, 3_000), &[]).unwrap());
    // limend "down": the fake has exited and a backlog has piled up.
    std::thread::sleep(Duration::from_millis(5_100));
    std::fs::write(d.join("spool/pending/x.json"), "{}").unwrap();
    std::fs::write(d.join("spool/pending/y.json"), "{}").unwrap();
    let hit = done_json(&q.submit(&qjob("w2", SMOKE_QUBO, 3_000), &[]).unwrap());
    assert_eq!(hit["cached"], true, "a cached answer needs no limend");
    let other = r#"{"qubo":[[["a","b"],1.0]],"fidelity_target":0.9,"credit_budget":0,"offline":true}"#;
    match q.submit(&qjob("w3", other, 3_000), &[]).unwrap().status {
        Status::Refused(w) => assert!(w.contains("limend is down or behind"), "{w}"),
        s => panic!("uncached request must still be refused: {s:?}"),
    }
    assert_eq!(std::fs::read_dir(d.join("spool/pending")).unwrap().count(), 2, "nothing new spooled");
}

#[test]
fn hardware_requests_are_never_cached() {
    let d = dir("nocache");
    fake_limend(d.join("spool"), Duration::ZERO, None, Duration::from_secs(5));
    let mut cfg = QpuConfig::new(d.join("spool")); cfg.est_job_secs = 0;
    let mut q = open(&d, cfg);
    let hw = SMOKE_QUBO.replace(r#""offline":true"#, r#""offline":false"#);
    for id in ["h1", "h2"] {
        let v = done_json(&q.submit(&qjob(id, &hw, 3_000), &[]).unwrap());
        assert!(v.get("cached").is_none());
    }
    assert_eq!(done_count(&d), 2);
    assert!(!d.join("spool/qhr-cache").exists() || std::fs::read_dir(d.join("spool/qhr-cache")).unwrap().count() == 0);
    // And prefetch refuses them outright.
    let lane = QpuLane::new(QpuConfig::new(d.join("spool")));
    assert!(lane.prefetch(&hw).unwrap_err().contains("offline requests only"));
}

#[test]
fn prefetch_then_run_adopts_the_prefetched_cert() {
    let d = dir("prefetch");
    let lane = QpuLane::new(QpuConfig::new(d.join("spool")));
    let id = lane.prefetch(SMOKE_QUBO).unwrap();
    assert!(id.starts_with("prefetch-"));
    assert_eq!(lane.prefetch(SMOKE_QUBO).unwrap(), id, "prefetch is idempotent while in flight");
    // limend works it ahead of the clock.
    fake_limend(d.join("spool"), Duration::ZERO, None, Duration::from_secs(5));
    let t = Instant::now();
    while !d.join(format!("spool/certs/{id}.json")).exists() {
        assert!(t.elapsed() < Duration::from_secs(3), "fake limend never certified the prefetch");
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut cfg = QpuConfig::new(d.join("spool")); cfg.est_job_secs = 0;
    let mut q = open(&d, cfg);
    let v = done_json(&q.submit(&qjob("p1", SMOKE_QUBO, 3_000), &[]).unwrap());
    assert_eq!(v["cached"], true);
    assert_eq!(v["job_id"], id);
    assert_eq!(v["exact_energy"], -2.0);
    assert_eq!(done_count(&d), 1, "only the prefetch ran");
    // Now it is in the cache proper: prefetch reports the key, not a new spool.
    assert!(!lane.prefetch(SMOKE_QUBO).unwrap().starts_with("prefetch-"));
}

#[test]
fn cache_key_ignores_job_id_and_term_order_but_not_the_problem() {
    let d = dir("key");
    fake_limend(d.join("spool"), Duration::ZERO, None, Duration::from_secs(5));
    let mut cfg = QpuConfig::new(d.join("spool")); cfg.est_job_secs = 0;
    let mut q = open(&d, cfg);
    let _ = done_json(&q.submit(&qjob("k1", SMOKE_QUBO, 3_000), &[]).unwrap());
    // Same terms, reordered: hit.
    let reordered = r#"{"qubo":[[["hub","hub"],-1.0],[["leaf1","leaf1"],-1.0],[["hub","leaf1"],2.0],[["leaf0","leaf0"],-1.0],[["hub","leaf0"],2.0]],"credit_budget":0.0,"fidelity_target":0.9,"offline":true}"#;
    assert_eq!(done_json(&q.submit(&qjob("k2", reordered, 3_000), &[]).unwrap())["cached"], true);
    // One weight changed: miss.
    let changed = SMOKE_QUBO.replace(r#"[["hub","hub"],-1.0]"#, r#"[["hub","hub"],-1.5]"#);
    assert!(done_json(&q.submit(&qjob("k3", &changed, 3_000), &[]).unwrap()).get("cached").is_none());
    // Different fidelity target: miss.
    let fid = SMOKE_QUBO.replace(r#""fidelity_target":0.9"#, r#""fidelity_target":0.5"#);
    assert!(done_json(&q.submit(&qjob("k4", &fid, 3_000), &[]).unwrap()).get("cached").is_none());
    assert_eq!(done_count(&d), 3);
}

#[test]
fn brute_force_and_shots_math() {
    use ductei_qhr::qpu::{brute_force, shots_to_optimum};
    let q = |a: &str, b: &str, w: f64| ((a.to_string(), b.to_string()), w);
    // Max-cut-ish: x+y-2xy rewards exactly one set; minimum is -1 at (1,0) or (0,1).
    let (e, a) = brute_force(&[q("x", "x", -1.0), q("y", "y", -1.0), q("x", "y", 2.0)], 16).unwrap();
    assert_eq!(e, -1.0);
    assert_eq!(a.iter().map(|(_, b)| *b as u32).sum::<u32>(), 1);
    assert!(brute_force(&[q("a", "a", 1.0)], 0).is_none(), "exact_max_vars = 0 turns it off");
    assert_eq!(shots_to_optimum(1.0, 0.99), Some(1));
    assert_eq!(shots_to_optimum(0.5, 0.99), Some(7));
    assert_eq!(shots_to_optimum(0.0, 0.99), None);
}
