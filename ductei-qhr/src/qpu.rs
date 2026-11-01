//! QPU lane: hands a QUBO job to limend through LIMEN's spool contract
//! (limen/limend/spool.py) and waits for the certificate.
//!
//!   spool/pending/{job_id}.json   written here, consumed by limend
//!   spool/certs/{job_id}.json     success: CertSummary (closed type, ductei-limen)
//!   spool/failed/{job_id}.json    failure with the reason attached
//!
//! ABA pre-flight is deterministic and never contacts a vendor:
//!   0. payload parses as exactly what `_request_from_json` accepts
//!   1. QUBO is non-empty, weights finite, variable count within `max_vars`
//!   2. fidelity_target in (0, 1], credit_budget >= 0
//!   3. limend is consuming: pending backlog below `max_backlog`
//!   4. queue estimate: backlog * `est_job_secs` must fit in the budget
//!
//! On a deadline miss the lane withdraws the request if limend has not
//! picked it up yet, so a missed job never runs (and never spends credits)
//! after the caller stopped waiting. If limend already took it, the cert
//! lands in certs/ orphaned and is reported as such on the next health call.

use crate::{Health, Job, Lane, LaneId};
use ductei_limen::CertSummary;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct QpuConfig {
    pub spool: PathBuf,
    /// Refuse QUBOs with more variables than this (LIMEN's practical ceiling
    /// on this box; cutting beyond it is reconstruction-bound).
    pub max_vars: usize,
    /// Refuse when this many requests are already pending: limend is down or behind.
    pub max_backlog: usize,
    /// Rough per-job time used for the queue estimate in pre-flight.
    pub est_job_secs: u64,
    pub poll: Duration,
}

impl QpuConfig {
    pub fn new(spool: impl Into<PathBuf>) -> Self {
        Self { spool: spool.into(), max_vars: 64, max_backlog: 8, est_job_secs: 30, poll: Duration::from_millis(100) }
    }
}

/// Mirror of what limend's `_request_from_json` reads. Unknown keys are
/// rejected here so a typo cannot silently drop a constraint.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    qubo: Vec<((String, String), f64)>,
    fidelity_target: f64,
    credit_budget: f64,
    #[serde(default)]
    job_id: Option<String>,
    #[serde(default)]
    force_tier: Option<u8>,
    #[serde(default)]
    physical_error_rate: Option<f64>,
    #[serde(default)]
    offline: Option<bool>,
}

pub struct QpuLane { cfg: QpuConfig }

impl QpuLane {
    pub fn new(cfg: QpuConfig) -> Self { Self { cfg } }
    fn dir(&self, sub: &str) -> PathBuf { self.cfg.spool.join(sub) }
    fn backlog(&self) -> std::io::Result<usize> {
        Ok(std::fs::read_dir(self.dir("pending"))?.filter_map(Result::ok).filter(|e| e.path().extension().is_some_and(|x| x == "json")).count())
    }

    /// Returns the variable count after validating the request.
    fn validate(&self, job: &Job) -> Result<usize, String> {
        let r: Request = serde_json::from_str(&job.payload).map_err(|e| format!("qpu.run payload is not a limend request: {e}"))?;
        if r.qubo.is_empty() { return Err("qubo is empty".into()); }
        let mut vars = std::collections::BTreeSet::new();
        for ((a, b), w) in &r.qubo {
            if !w.is_finite() { return Err(format!("qubo weight for ({a},{b}) is not finite")); }
            if a.is_empty() || b.is_empty() { return Err("qubo variable names must be non-empty".into()); }
            vars.insert(a.as_str()); vars.insert(b.as_str());
        }
        if vars.len() > self.cfg.max_vars { return Err(format!("{} variables exceeds the lane ceiling of {}", vars.len(), self.cfg.max_vars)); }
        if !(r.fidelity_target > 0.0 && r.fidelity_target <= 1.0) { return Err(format!("fidelity_target {} must be in (0, 1]", r.fidelity_target)); }
        if !(r.credit_budget >= 0.0 && r.credit_budget.is_finite()) { return Err(format!("credit_budget {} must be >= 0", r.credit_budget)); }
        if let Some(t) = r.force_tier { if t > 3 { return Err(format!("force_tier {t} out of range 0..=3")); } }
        if let Some(p) = r.physical_error_rate { if !(0.0..1.0).contains(&p) { return Err(format!("physical_error_rate {p} must be in [0, 1)")); } }
        if let Some(id) = &r.job_id { if id != &job.task.id { return Err(format!("payload job_id {id:?} must match task id {:?}", job.task.id)); } }
        let _ = r.offline;
        Ok(vars.len())
    }
}

impl Lane for QpuLane {
    fn id(&self) -> LaneId { LaneId::Qpu }

    fn health(&self) -> Health {
        for sub in ["pending", "certs", "failed", "done"] {
            if !self.dir(sub).is_dir() { return Health::Unavailable(format!("spool dir missing: {}", self.dir(sub).display())); }
        }
        match self.backlog() {
            Ok(n) if n >= self.cfg.max_backlog => Health::Unavailable(format!("{n} requests pending; limend is down or behind")),
            Ok(_) => Health::Ready,
            Err(e) => Health::Unavailable(format!("cannot read spool: {e}")),
        }
    }

    fn preflight(&self, job: &Job) -> Result<(), String> {
        if job.op != "qpu.run" { return Err(format!("qpu lane has no op {:?}", job.op)); }
        self.validate(job)?;
        let backlog = self.backlog().map_err(|e| e.to_string())?;
        let est = (backlog as u64 + 1).saturating_mul(self.cfg.est_job_secs).saturating_mul(1000);
        if est > job.budget_ms {
            return Err(format!("queue estimate {est} ms ({backlog} ahead, ~{} s each) exceeds budget {} ms", self.cfg.est_job_secs, job.budget_ms));
        }
        Ok(())
    }

    fn run(&self, job: &Job, deadline: Instant) -> Result<String, String> {
        let id = &job.task.id;
        let pending = self.dir("pending").join(format!("{id}.json"));
        let cert = self.dir("certs").join(format!("{id}.json"));
        let failed = self.dir("failed").join(format!("{id}.json"));
        if cert.exists() || failed.exists() || pending.exists() {
            return Err(format!("job id {id:?} already exists in the spool; ids must be fresh"));
        }
        // Set job_id inside the request so limend keys its files by it.
        let mut v: serde_json::Value = serde_json::from_str(&job.payload).map_err(|e| e.to_string())?;
        v["job_id"] = serde_json::Value::String(id.clone());
        let tmp = self.dir("pending").join(format!("{id}.json.part"));
        std::fs::write(&tmp, serde_json::to_vec_pretty(&v).map_err(|e| e.to_string())?).map_err(|e| format!("spool write: {e}"))?;
        std::fs::rename(&tmp, &pending).map_err(|e| format!("spool publish: {e}"))?;

        loop {
            if cert.exists() {
                let text = read_settled(&cert)?;
                let c = CertSummary::from_json(&text).map_err(|e| format!("cert for {id} unreadable: {e}"))?;
                return serde_json::to_string(&serde_json::json!({
                    "job_id": c.job_id, "backend": c.backend, "tier": c.tier,
                    "success_probability": c.success_probability, "target_met": c.target_met, "lamport": c.lamport,
                })).map_err(|e| e.to_string());
            }
            if failed.exists() {
                let text = read_settled(&failed)?;
                let why = serde_json::from_str::<serde_json::Value>(&text).ok()
                    .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
                    .unwrap_or_else(|| "limend reported failure".into());
                return Err(format!("limend: {why}"));
            }
            if Instant::now() >= deadline {
                // Withdraw if limend has not taken it; otherwise it is in flight and will orphan.
                let withdrawn = std::fs::remove_file(&pending).is_ok();
                return Err(if withdrawn { "deadline: request withdrawn before limend picked it up".to_string() }
                           else { format!("deadline: limend already took {id}; its cert will land orphaned in certs/") });
            }
            std::thread::sleep(self.cfg.poll.min(deadline.saturating_duration_since(Instant::now())));
        }
    }
}

/// limend writes files whole, but read twice to be safe against a torn observation.
fn read_settled(p: &Path) -> Result<String, String> {
    let a = std::fs::read_to_string(p).map_err(|e| e.to_string())?;
    std::thread::sleep(Duration::from_millis(5));
    let b = std::fs::read_to_string(p).map_err(|e| e.to_string())?;
    if a == b { Ok(a) } else { Err(format!("{} still being written", p.display())) }
}
