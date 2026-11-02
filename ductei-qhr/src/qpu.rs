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
//!
//! Ahead-of-clock cache (offline requests only, where limend is a
//! deterministic simulator): results are stored under
//! `spool/qhr-cache/{key}.json`, keyed by a sha256 over the request minus
//! `job_id`. A repeat request returns in microseconds with `cached: true` and
//! the job id that produced it. `prefetch` spools a request now under
//! `prefetch-{key16}` without waiting; the next `run` of the same request
//! adopts that cert instead of spooling again. Hardware (non-offline)
//! requests are never cached: a replayed hardware sample is not a new run.
//!
//! Exact check (QUBOs up to `exact_max_vars`): QHR brute-forces the optimum
//! itself and reports `exact_energy`, `exact_assignment`, and
//! `shots_to_optimum_99` (how many samples at limend's `success_probability`
//! find the optimum with 99% confidence). No change to `CertSummary`.

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
    /// Serve and fill the offline-result cache (`spool/qhr-cache`).
    pub cache: bool,
    /// Brute-force the exact optimum for QUBOs with at most this many variables (0 = off).
    pub exact_max_vars: usize,
}

impl QpuConfig {
    pub fn new(spool: impl Into<PathBuf>) -> Self {
        Self { spool: spool.into(), max_vars: 64, max_backlog: 8, est_job_secs: 30, poll: Duration::from_millis(100), cache: true, exact_max_vars: 16 }
    }
}

/// sha256 over the request with `job_id` excluded and terms sorted, so the
/// same problem keys the same however the caller ordered or named the job.
fn cache_key(r: &Request) -> String {
    let mut terms: Vec<String> = r.qubo.iter().map(|((a, b), w)| format!("{a}\u{1f}{b}\u{1f}{:e}", w)).collect();
    terms.sort();
    let canon = format!(
        "limen.req.v1|{:e}|{:e}|{:?}|{:?}|{:?}|{}",
        r.fidelity_target, r.credit_budget, r.force_tier, r.physical_error_rate.map(|p| format!("{p:e}")), r.offline, terms.join("\u{1e}")
    );
    ductei_mcp::sha256_hex(canon.as_bytes())
}

/// Minimum energy and one optimal assignment, by enumeration.
/// Energy convention matches LIMEN: sum of w * x_a * x_b (diagonal terms are linear).
pub fn brute_force(qubo: &[((String, String), f64)], max_vars: usize) -> Option<(f64, Vec<(String, u8)>)> {
    let mut names: Vec<&str> = qubo.iter().flat_map(|((a, b), _)| [a.as_str(), b.as_str()]).collect();
    names.sort_unstable();
    names.dedup();
    let n = names.len();
    if n == 0 || n > max_vars || n > 24 { return None; }
    let idx = |s: &str| names.binary_search(&s).unwrap();
    let terms: Vec<(usize, usize, f64)> = qubo.iter().map(|((a, b), w)| (idx(a), idx(b), *w)).collect();
    let (mut best_e, mut best_m) = (f64::INFINITY, 0u32);
    for m in 0u32..(1u32 << n) {
        let e: f64 = terms.iter().filter(|(i, j, _)| m >> i & 1 == 1 && m >> j & 1 == 1).map(|(_, _, w)| w).sum();
        if e < best_e { best_e = e; best_m = m; }
    }
    Some((best_e, names.iter().enumerate().map(|(i, s)| (s.to_string(), (best_m >> i & 1) as u8)).collect()))
}

/// Samples needed to see an optimal bitstring at least once with confidence `conf`.
pub fn shots_to_optimum(p: f64, conf: f64) -> Option<u64> {
    if !(p > 0.0 && p <= 1.0) || !(conf > 0.0 && conf < 1.0) { return None; }
    if p >= 1.0 { return Some(1); }
    Some(((1.0 - conf).ln() / (1.0 - p).ln()).ceil().max(1.0) as u64)
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

    /// Offline request whose result is already in `qhr-cache` (no limend needed).
    fn cache_hit(&self, job: &Job) -> bool {
        self.cfg.cache
            && serde_json::from_str::<Request>(&job.payload)
                .map(|r| r.offline == Some(true) && self.cache_path(&cache_key(&r)).exists())
                .unwrap_or(false)
    }
    fn cache_path(&self, key: &str) -> PathBuf { self.dir("qhr-cache").join(format!("{key}.json")) }
    fn prefetch_id(key: &str) -> String { format!("prefetch-{}", &key[..16]) }

    /// Spool `payload` now, under a key-derived id, and return without waiting.
    /// A later `run` of the same request adopts the cert. Offline requests only.
    /// Returns the spooled id, or the cache key when the result is already cached.
    pub fn prefetch(&self, payload: &str) -> Result<String, String> {
        let r: Request = serde_json::from_str(payload).map_err(|e| format!("prefetch payload is not a limend request: {e}"))?;
        if r.offline != Some(true) { return Err("prefetch is for offline requests only; hardware runs are never cached".into()); }
        let key = cache_key(&r);
        if self.cache_path(&key).exists() { return Ok(key); }
        let id = Self::prefetch_id(&key);
        for sub in ["pending", "certs", "done"] {
            if self.dir(sub).join(format!("{id}.json")).exists() { return Ok(id); }
        }
        let mut v: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
        v["job_id"] = serde_json::Value::String(id.clone());
        publish(&self.dir("pending"), &id, &v)?;
        Ok(id)
    }

    /// Cached result for `key`, or a prefetched cert adopted into the cache.
    fn cached(&self, key: &str, r: &Request) -> Option<String> {
        if let Ok(text) = std::fs::read_to_string(self.cache_path(key)) {
            let mut v: serde_json::Value = serde_json::from_str(&text).ok()?;
            v["cached"] = true.into();
            return serde_json::to_string(&v).ok();
        }
        let cert = self.dir("certs").join(format!("{}.json", Self::prefetch_id(key)));
        let c = CertSummary::from_json(&read_settled(&cert).ok()?).ok()?;
        let detail = self.detail(&c, r);
        self.store(key, &detail);
        let mut v = detail;
        v["cached"] = true.into();
        serde_json::to_string(&v).ok()
    }

    fn store(&self, key: &str, detail: &serde_json::Value) {
        let dir = self.dir("qhr-cache");
        if std::fs::create_dir_all(&dir).is_ok() { let _ = publish(&dir, key, detail); }
    }

    /// Closed CertSummary fields plus QHR's own exact check.
    fn detail(&self, c: &CertSummary, r: &Request) -> serde_json::Value {
        let mut v = serde_json::json!({
            "job_id": c.job_id, "backend": c.backend, "tier": c.tier,
            "success_probability": c.success_probability, "target_met": c.target_met, "lamport": c.lamport,
            "shots_to_optimum_99": shots_to_optimum(c.success_probability, 0.99),
        });
        if let Some((e, a)) = brute_force(&r.qubo, self.cfg.exact_max_vars) {
            v["exact_energy"] = e.into();
            v["exact_assignment"] = a.into_iter().map(|(k, b)| (k, serde_json::Value::from(b))).collect::<serde_json::Map<_, _>>().into();
        }
        v
    }
}

/// Write `{dir}/{name}.json` atomically (tmp + rename) so readers never see a torn file.
fn publish(dir: &Path, name: &str, v: &serde_json::Value) -> Result<(), String> {
    let tmp = dir.join(format!("{name}.json.part"));
    std::fs::write(&tmp, serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?).map_err(|e| format!("spool write: {e}"))?;
    std::fs::rename(&tmp, dir.join(format!("{name}.json"))).map_err(|e| format!("spool publish: {e}"))
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

    fn serves_offline(&self, job: &Job) -> bool {
        job.op == "qpu.run" && self.cache_hit(job)
    }

    fn preflight(&self, job: &Job) -> Result<(), String> {
        if job.op != "qpu.run" { return Err(format!("qpu lane has no op {:?}", job.op)); }
        self.validate(job)?;
        // A cached offline result never touches limend, so backlog and queue
        // estimate do not apply to it.
        if self.cache_hit(job) { return Ok(()); }
        let backlog = self.backlog().map_err(|e| e.to_string())?;
        let est = (backlog as u64 + 1).saturating_mul(self.cfg.est_job_secs).saturating_mul(1000);
        if est > job.budget_ms {
            return Err(format!("queue estimate {est} ms ({backlog} ahead, ~{} s each) exceeds budget {} ms", self.cfg.est_job_secs, job.budget_ms));
        }
        Ok(())
    }

    fn run(&self, job: &Job, deadline: Instant) -> Result<String, String> {
        let id = &job.task.id;
        let req: Request = serde_json::from_str(&job.payload).map_err(|e| e.to_string())?;
        let key = (self.cfg.cache && req.offline == Some(true)).then(|| cache_key(&req));
        if let Some(k) = &key {
            if let Some(hit) = self.cached(k, &req) { return Ok(hit); }
        }
        let pending = self.dir("pending").join(format!("{id}.json"));
        let cert = self.dir("certs").join(format!("{id}.json"));
        let failed = self.dir("failed").join(format!("{id}.json"));
        if cert.exists() || failed.exists() || pending.exists() {
            return Err(format!("job id {id:?} already exists in the spool; ids must be fresh"));
        }
        // Set job_id inside the request so limend keys its files by it.
        let mut v: serde_json::Value = serde_json::from_str(&job.payload).map_err(|e| e.to_string())?;
        v["job_id"] = serde_json::Value::String(id.clone());
        publish(&self.dir("pending"), id, &v)?;

        loop {
            if cert.exists() {
                let text = read_settled(&cert)?;
                let c = CertSummary::from_json(&text).map_err(|e| format!("cert for {id} unreadable: {e}"))?;
                let detail = self.detail(&c, &req);
                if let Some(k) = &key { self.store(k, &detail); }
                return serde_json::to_string(&detail).map_err(|e| e.to_string());
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
