//! ductei-qhr: the Quantum Hybrid Runtime job plane for ATRIUM.
//!
//! Pipeline for every job, in this order:
//!
//! 0. CANON gate (ductei-router, deny-by-default, unchanged).
//! 1. Tier (ductei-router `route`, deterministic, unchanged).
//! 2. Lane pick: local tiers map to a local lane; remote tiers are refused,
//!    because QHR executes on this machine only.
//! 3. ABA pre-flight ("act before action"), deterministic: lane registered,
//!    lane healthy, op known to the lane, and a predicted-miss check that
//!    refuses a job whose budget is below the lane's measured p99.
//! 4. Run under a deadline (the budget counts from submit, gate included).
//! 5. Hash-chained receipt, written before the report is returned
//!    (persistence before ack), in the Verified or Fast chain.
//!
//! Real time: a deadline miss is an outcome, receipted like any other,
//! never silent. Lanes run on std threads and cannot be preempted, so a lane
//! must honour the deadline it is handed; the runtime only stops waiting.
//!
//! The router decides and records; QHR executes. QHR reuses the router's
//! gate and routing but holds its receipt logs open, so a decision does not
//! re-verify the whole chain on every call.
#![forbid(unsafe_code)]

use ductei_mcp::{Durability, ReceiptBody, ReceiptLog, SignCfg};
use ductei_router::{route, sha256_json, Canon, Kind, Outcome, Stats, Task, Tier, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{mpsc, Arc};
use std::time::Instant;

pub mod lanes;
pub mod mcp;
pub mod qpu;
pub mod weight;
pub use weight::{Evidence, Weighter};

/// A lane chosen to run, with the weighter's explanation.
type Picked = (Arc<dyn Lane>, String);
/// Why no lane ran: the lane blamed (when exactly one was tried) and the reason.
type Refusal = (Option<LaneId>, String);

/// Lanes a job may run on, given tier and op. Ops carry a lane prefix
/// (`cpu.`, `cuda.`, `qpu.`, `llm.`); an unprefixed op may run on any
/// registered lane that accepts it in pre-flight, and the weighter chooses.
/// Order is the tie-break order.
fn candidates(tier: Tier, op: &str) -> Result<Vec<LaneId>, String> {
    const ALL: [LaneId; 4] = [LaneId::Cpu, LaneId::Cuda, LaneId::Qpu, LaneId::Llm];
    match tier {
        Tier::TQuantum => Ok(vec![LaneId::Qpu]),
        Tier::T0Local => Ok(match op.split_once('.').map(|(p, _)| p) {
            Some("llm") => vec![LaneId::Llm],
            Some("cuda") => vec![LaneId::Cuda],
            Some("qpu") => vec![LaneId::Qpu],
            Some("cpu") => vec![LaneId::Cpu],
            _ => ALL.to_vec(),
        }),
        t => Err(format!("tier {t:?} is remote; QHR runs local lanes only")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneId { Cpu, Cuda, Qpu, Llm }

impl LaneId {
    pub fn as_str(self) -> &'static str {
        match self { LaneId::Cpu => "cpu", LaneId::Cuda => "cuda", LaneId::Qpu => "qpu", LaneId::Llm => "llm" }
    }
}

/// Verified: every receipt fsynced. Fast: batched fsync (bounded loss
/// window on crash), same chain, same per-receipt signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assurance { Verified, Fast }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health { Ready, Unavailable(String) }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    /// Goes through the CANON gate and the router exactly as the router sees it.
    /// Local compute should set `private = true` (pinned to T0 by the router).
    pub task: Task,
    /// Lane operation, prefixed by lane: `cpu.sha256`, `llm.complete`, `qpu.run`, `cuda.*`.
    pub op: String,
    #[serde(default)]
    pub payload: String,
    /// Wall-clock budget from submit to result, gate included.
    pub budget_ms: u64,
    #[serde(default = "verified")]
    pub assurance: Assurance,
}
fn verified() -> Assurance { Assurance::Verified }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "detail")]
pub enum Status {
    Done(String),
    Denied(String),
    NeedsApproval(Vec<String>),
    /// Pre-flight said no; the lane never ran.
    Refused(String),
    LaneError(String),
    DeadlineMissed { budget_ms: u64 },
}

impl Status {
    pub fn label(&self) -> &'static str {
        match self {
            Status::Done(_) => "done",
            Status::Denied(_) => "denied",
            Status::NeedsApproval(_) => "needs_approval",
            Status::Refused(_) => "refused",
            Status::LaneError(_) => "lane_error",
            Status::DeadlineMissed { .. } => "deadline_missed",
        }
    }
    fn ran(&self) -> bool { matches!(self, Status::Done(_) | Status::LaneError(_) | Status::DeadlineMissed { .. }) }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub task_id: String,
    pub tier: Tier,
    pub lane: Option<LaneId>,
    pub status: Status,
    /// End to end, submit to receipt written.
    pub elapsed_us: u64,
    /// Submit to verdict, before the receipt write. This is the part the
    /// deadline bounds; the durable fsync after it depends on the disk.
    #[serde(default)]
    pub decided_us: u64,
    pub receipt: String,
    /// How the lane was chosen: weighter name and each candidate's weight, or
    /// why no candidate survived. Receipted via the result hash.
    #[serde(default)]
    pub pick_why: String,
}

pub trait Lane: Send + Sync {
    fn id(&self) -> LaneId;
    /// Must be cheap: it runs inside the job's budget. Cache slow probes.
    fn health(&self) -> Health;
    /// True when this job can be answered without the lane's backend (a
    /// cached result), so an Unavailable health must not refuse it. Must be
    /// cheap. Default: false.
    fn serves_offline(&self, _job: &Job) -> bool { false }
    /// Deterministic check before anything runs. Default: accept.
    fn preflight(&self, _job: &Job) -> Result<(), String> { Ok(()) }
    /// Do the work. `deadline` is absolute; honour it.
    fn run(&self, job: &Job, deadline: Instant) -> Result<String, String>;
}

/// Latency samples kept per lane (ring), and the minimum before p99 is trusted.
pub const LATENCY_WINDOW: usize = 256;
pub const MIN_SAMPLES_FOR_PREDICTION: usize = 20;
/// Outcomes kept in memory for the router's escalation rule (it reads the last 10 per kind/tier).
const OUTCOME_WINDOW: usize = 512;

pub struct Qhr {
    /// outcomes.jsonl held open: reopening it per job costs ~1 ms on Windows.
    /// Same line format as ductei_router::append_outcome, so the router reads it.
    outcomes_file: File,
    canon: Canon,
    lanes: HashMap<LaneId, Arc<dyn Lane>>,
    verified: ReceiptLog,
    fast: ReceiptLog,
    outcomes: Vec<Outcome>,
    latency: HashMap<LaneId, Vec<u64>>,
    /// (ok, total) runs per lane and job kind; feeds the weighter. In-memory
    /// only: the receipt chain is the record, this is a cache of it.
    kind_runs: HashMap<(LaneId, Kind), (u32, u32)>,
    weighter: Box<dyn Weighter>,
}

impl Qhr {
    /// `state` holds canon.toml (optional), outcomes.jsonl, and the two
    /// receipt chains under `verified/` and `fast/`.
    pub fn open(state: &Path, sign: &SignCfg, fast: Durability) -> Result<Self, String> {
        for sub in ["verified", "fast"] {
            std::fs::create_dir_all(state.join(sub)).map_err(|e| format!("{}: {e}", state.join(sub).display()))?;
        }
        let canon = Canon::load(state)?;
        // One key at the state root signs both chains: one fingerprint to pin.
        let verified = ReceiptLog::open_in(&state.join("verified"), state, sign, Durability::default())?;
        let fast = ReceiptLog::open_in(&state.join("fast"), state, sign, fast)?;
        let op = state.join("outcomes.jsonl");
        let outcomes = load_outcomes(&op)?;
        let outcomes_file = OpenOptions::new().create(true).append(true).open(&op).map_err(|e| format!("{}: {e}", op.display()))?;
        Ok(Self { outcomes_file, canon, lanes: HashMap::new(), verified, fast, outcomes, latency: HashMap::new(), kind_runs: HashMap::new(), weighter: Box::new(weight::Uniform) })
    }

    /// Replace the lane weighter. Default is `weight::Uniform` (prefix picker behaviour).
    pub fn set_weighter(&mut self, w: Box<dyn Weighter>) { self.weighter = w; }
    pub fn weighter_name(&self) -> &'static str { self.weighter.name() }

    /// (ok, total) runs of `kind` on `lane` since open.
    pub fn kind_runs(&self, lane: LaneId, kind: Kind) -> (u32, u32) { self.kind_runs.get(&(lane, kind)).copied().unwrap_or((0, 0)) }

    /// Exactly the rows the router's escalation rule can read: for this kind,
    /// the last 10 per tier, in order. Same answer as passing every row,
    /// without cloning the whole window on every job.
    fn stats_for(&self, kind: Kind) -> Stats {
        let mut per_tier: HashMap<Tier, usize> = HashMap::new();
        let mut rows: Vec<Outcome> = Vec::with_capacity(40);
        for o in self.outcomes.iter().rev().filter(|o| o.kind == kind) {
            let n = per_tier.entry(o.tier).or_insert(0);
            if *n < 10 { *n += 1; rows.push(o.clone()); }
        }
        rows.reverse();
        Stats::from_rows(rows)
    }

    pub fn register(&mut self, lane: Arc<dyn Lane>) { self.lanes.insert(lane.id(), lane); }

    pub fn receipts(&self, a: Assurance) -> &ReceiptLog {
        match a { Assurance::Verified => &self.verified, Assurance::Fast => &self.fast }
    }

    /// fsync anything the Fast chain has pending. Call before shutdown.
    pub fn flush(&mut self) -> std::io::Result<()> { self.verified.flush()?; self.fast.flush() }

    /// (p50, p99, samples) of measured lane run time, in microseconds.
    pub fn latency(&self, lane: LaneId) -> Option<(u64, u64, usize)> {
        let v = self.latency.get(&lane)?;
        if v.is_empty() { return None; }
        let mut s = v.clone();
        s.sort_unstable();
        let at = |p: f64| s[((s.len() - 1) as f64 * p).round() as usize];
        Some((at(0.50), at(0.99), s.len()))
    }

    pub fn submit(&mut self, job: &Job, approvals: &[String]) -> Result<Report, String> {
        let t0 = Instant::now();
        let deadline = t0 + std::time::Duration::from_millis(job.budget_ms);
        let verdict = self.canon.check(&job.task, approvals);
        let (tier, _why, _escalated) = route(&job.task, &self.stats_for(job.task.kind));

        let (lane, status, run_us, pick_why) = match verdict {
            Verdict::Deny(r) => (None, Status::Denied(r), 0, String::new()),
            Verdict::NeedsApproval(n) => (None, Status::NeedsApproval(n), 0, String::new()),
            Verdict::Allow => match self.pick(tier, job) {
                Err((lane, why)) => (lane, Status::Refused(why), 0, String::new()),
                Ok((l, why)) => { let id = l.id(); let (s, us) = run_with_deadline(l, job, deadline); (Some(id), s, us, why) }
            },
        };

        let decided_us = t0.elapsed().as_micros() as u64;
        if let (Some(id), true) = (lane, status.ran()) {
            let v = self.latency.entry(id).or_default();
            if v.len() == LATENCY_WINDOW { v.remove(0); }
            v.push(run_us);
            let k = self.kind_runs.entry((id, job.task.kind)).or_insert((0, 0));
            k.1 = k.1.saturating_add(1);
            if matches!(status, Status::Done(_)) { k.0 = k.0.saturating_add(1); }
            let o = Outcome { task_id: job.task.id.clone(), kind: job.task.kind, tier, ok: matches!(status, Status::Done(_)) };
            // Best effort, no fsync: the receipt below is the record of truth;
            // outcomes only feed escalation.
            if let Ok(line) = serde_json::to_string(&o) { let _ = writeln!(self.outcomes_file, "{line}"); }
            if self.outcomes.len() == OUTCOME_WINDOW { self.outcomes.remove(0); }
            self.outcomes.push(o);
        }

        let scope = format!("qhr:{}", lane.map(LaneId::as_str).unwrap_or("none"));
        let result = sha256_json(&(&job.task.id, tier, lane, &status, &pick_why));
        let body = ReceiptBody::new(job.task.id.clone(), scope, status.label(), 0, 0, sha256_json(job), result);
        let log = match job.assurance { Assurance::Verified => &mut self.verified, Assurance::Fast => &mut self.fast };
        let r = log.record(body).map_err(|e| format!("receipt write failed, result withheld: {e}"))?;
        Ok(Report { task_id: job.task.id.clone(), tier, lane, status, elapsed_us: t0.elapsed().as_micros() as u64, decided_us, receipt: r.hash, pick_why })
    }

    /// Candidate scan + weighting. Every candidate goes through the same
    /// deterministic pre-flight as before; survivors are weighted and the
    /// highest runs. On refusal the error carries the lane when exactly one
    /// candidate was tried (unchanged messages), else None with every reason.
    fn pick(&self, tier: Tier, job: &Job) -> Result<Picked, Refusal> {
        let cands = candidates(tier, &job.op).map_err(|e| (None, e))?;
        let single = cands.len() == 1;
        let mut ok: Vec<(Arc<dyn Lane>, LaneId, f64)> = Vec::with_capacity(cands.len());
        let mut why: Vec<String> = Vec::new();
        for id in cands {
            match self.preflight(id, job) {
                Err(e) => { if single { return Err((self.lanes.contains_key(&id).then_some(id), e)); } why.push(format!("{}: {e}", id.as_str())); }
                Ok(l) => {
                    let ev = Evidence { latency_us: self.latency(id), kind_runs: self.kind_runs(id, job.task.kind), budget_us: job.budget_ms.saturating_mul(1000) };
                    ok.push((l, id, self.weighter.weight(id, job, &ev)));
                }
            }
        }
        let scored: Vec<(LaneId, f64)> = ok.iter().map(|(_, id, w)| (*id, *w)).collect();
        let Some(i) = weight::argmax(&scored) else {
            let zero = if ok.is_empty() { String::new() } else { format!("; all weights zero under {}", self.weighter.name()) };
            return Err((None, format!("no lane accepted {:?}: {}{zero}", job.op, why.join("; "))));
        };
        let detail = scored.iter().map(|(id, w)| format!("{}={w:.3}", id.as_str())).collect::<Vec<_>>().join(",");
        let (lane, id, _) = ok.swap_remove(i);
        Ok((lane, format!("{}:{}<-[{detail}]", self.weighter.name(), id.as_str())))
    }

    fn preflight(&self, id: LaneId, job: &Job) -> Result<Arc<dyn Lane>, String> {
        if job.budget_ms == 0 { return Err("budget_ms must be > 0".into()); }
        let lane = self.lanes.get(&id).cloned().ok_or_else(|| format!("no {} lane registered", id.as_str()))?;
        if let Health::Unavailable(why) = lane.health() {
            if !lane.serves_offline(job) { return Err(format!("{} lane unavailable: {why}", id.as_str())); }
        }
        if let Some((_, p99, n)) = self.latency(id) {
            if n >= MIN_SAMPLES_FOR_PREDICTION && p99 > job.budget_ms.saturating_mul(1000) {
                return Err(format!("predicted miss: budget {} ms is below {} lane p99 {:.3} ms over {n} runs", job.budget_ms, id.as_str(), p99 as f64 / 1000.0));
            }
        }
        lane.preflight(job)?;
        Ok(lane)
    }
}

fn run_with_deadline(lane: Arc<dyn Lane>, job: &Job, deadline: Instant) -> (Status, u64) {
    let budget_us = job.budget_ms.saturating_mul(1000);
    let Some(left) = deadline.checked_duration_since(Instant::now()) else {
        return (Status::DeadlineMissed { budget_ms: job.budget_ms }, budget_us);
    };
    let (tx, rx) = mpsc::sync_channel(1);
    let j = job.clone();
    let start = Instant::now();
    let spawned = std::thread::Builder::new().name(format!("qhr-{}", lane.id().as_str())).spawn(move || {
        let _ = tx.send(lane.run(&j, deadline));
    });
    if let Err(e) = spawned { return (Status::LaneError(format!("spawn: {e}")), 0); }
    match rx.recv_timeout(left) {
        Ok(Ok(out)) => (Status::Done(out), start.elapsed().as_micros() as u64),
        Ok(Err(e)) => (Status::LaneError(e), start.elapsed().as_micros() as u64),
        // A miss counts as at least the full budget in the latency window, so p99 sees it.
        Err(_) => (Status::DeadlineMissed { budget_ms: job.budget_ms }, budget_us),
    }
}

/// Verdicts a QHR receipt may carry. Anything else is a forged or foreign line.
pub const VERDICTS: [&str; 6] = ["done", "denied", "needs_approval", "refused", "lane_error", "deadline_missed"];

/// Verify one QHR chain (`<state>/verified` or `<state>/fast`): hash chain,
/// signatures, key pin, anchors, and that every verdict and scope is one QHR
/// writes. Same trust model as the gate's verifier. The public key lives at
/// the state root; when the caller pinned nothing, it is read from there and
/// the report carries the gate's "unpinned" warning.
pub fn verify_state(state: &Path, chain: &str, trust: &ductei_mcp::VerifyTrust) -> Result<ductei_mcp::VerifyReport, String> {
    let mut t = ductei_mcp::VerifyTrust { pubkey: trust.pubkey.clone(), fingerprint: trust.fingerprint.clone(), allow_unpinned: trust.allow_unpinned, anchors: trust.anchors.clone(), pinned_head: trust.pinned_head.clone() };
    if t.pubkey.is_none() {
        if let Some((_, pk)) = ductei_mcp::Signer::load_public(state)? {
            if t.fingerprint.is_none() && !t.allow_unpinned {
                return Err("public key taken from the state dir and not pinned: pass --pubkey <file> or --fingerprint <hex> (or --allow-unpinned to check integrity only)".into());
            }
            t.pubkey = Some(pk);
        }
    }
    verify(&state.join(chain), &t)
}

/// Verify one chain directory with the trust given (no key lookup at the
/// state root). `verify_state` is the usual entry point.
pub fn verify(chain_dir: &Path, trust: &ductei_mcp::VerifyTrust) -> Result<ductei_mcp::VerifyReport, String> {
    ductei_mcp::verify_chain(chain_dir, trust, |r, rep| {
        let s = r.body.seq;
        if !VERDICTS.contains(&r.body.verdict.as_str()) { rep.errors.push(format!("seq {s}: not a QHR verdict: {}", r.body.verdict)); }
        if !r.body.scope.starts_with("qhr:") { rep.errors.push(format!("seq {s}: not a QHR scope: {}", r.body.scope)); }
        if r.body.call_sha256.len() != 64 || r.body.result_sha256.len() != 64 { rep.errors.push(format!("seq {s}: job/result hash malformed")); }
    })
}

fn load_outcomes(path: &Path) -> Result<Vec<Outcome>, String> {
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut v: Vec<Outcome> = BufReader::new(f).lines().map_while(Result::ok).filter_map(|l| serde_json::from_str(&l).ok()).collect();
    if v.len() > OUTCOME_WINDOW { v.drain(..v.len() - OUTCOME_WINDOW); }
    Ok(v)
}
