//! ductei-router: the ATRIUM task router.
//!
//! Pipeline: Task -> CANON gate (deny-by-default) -> deterministic tier choice
//! -> hash-chained receipt (ductei-mcp ReceiptLog, ML-DSA-65 with `sign`).
//! The router never executes work. It decides who may, and records why.

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier { T0Local, T1Claude, T2Fleet, TQuantum }

impl Tier {
    fn escalate(self) -> Self {
        match self { Tier::T0Local => Tier::T1Claude, Tier::T1Claude => Tier::T2Fleet, t => t }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind { Classify, Chat, Code, Research, Quantum }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "target")]
pub enum Effect {
    Read(PathBuf),
    Write(PathBuf),
    Delete(PathBuf),
    Commit,
    Push,
    Send,
    Purchase,
    Network(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub intent: String,
    pub kind: Kind,
    #[serde(default)]
    pub criticality: u8,
    /// Private data never leaves the machine: pinned to T0.
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub effects: Vec<Effect>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "verdict", content = "detail")]
pub enum Verdict { Allow, NeedsApproval(Vec<String>), Deny(String) }

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self { Verdict::Allow => "allow", Verdict::NeedsApproval(_) => "needs_approval", Verdict::Deny(_) => "deny" }
    }
}

/// CANON hard invariants. Paths outside `roots` or on a denied drive are
/// refused outright; irreversible effects need an explicit approval token.
pub struct Canon { pub roots: Vec<PathBuf>, pub denied_drives: Vec<char> }

impl Default for Canon {
    fn default() -> Self {
        Self { roots: vec![PathBuf::from(r"D:\ATRIUM"), PathBuf::from(r"D:\dev")], denied_drives: vec!['C'] }
    }
}

/// Optional overrides, read from `<state>/canon.toml`:
/// ```toml
/// roots = ['D:\ATRIUM', 'D:\dev', 'D:\LIMEN']
/// denied_drives = ['C']
/// ```
/// Missing file or missing key keeps the default. The denied-drive list can
/// only grow: `C` stays denied whatever the file says.
#[derive(Deserialize, Default)]
struct CanonFile { #[serde(default)] roots: Option<Vec<PathBuf>>, #[serde(default)] denied_drives: Option<Vec<char>> }

impl Canon {
    pub fn load(state: &Path) -> Result<Self, String> {
        let mut c = Canon::default();
        let p = state.join("canon.toml");
        let text = match std::fs::read_to_string(&p) { Ok(t) => t, Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(c), Err(e) => return Err(format!("{}: {e}", p.display())) };
        let f: CanonFile = toml::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;
        if let Some(r) = f.roots { if !r.is_empty() { c.roots = r; } }
        if let Some(d) = f.denied_drives { for ch in d { if !c.denied_drives.iter().any(|x| x.eq_ignore_ascii_case(&ch)) { c.denied_drives.push(ch); } } }
        // A root on a denied drive would be contradictory; refuse to start.
        for r in &c.roots {
            if let Some(reason) = c.path_reason(r) { if reason.starts_with("drive") { return Err(format!("canon.toml: {reason}")); } }
        }
        Ok(c)
    }
}

/// Receipt signing config, read from `<state>/sign.toml` (same shape as the
/// `[sign]` table of a ductei-mcp gate config, without the table header).
/// Missing file means unsigned hash-chained receipts (scheme = "none").
pub fn load_sign(state: &Path) -> Result<ductei_mcp::SignCfg, String> {
    let p = state.join("sign.toml");
    match std::fs::read_to_string(&p) {
        Ok(t) => toml::from_str(&t).map_err(|e| format!("{}: {e}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ductei_mcp::SignCfg::default()),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

fn norm(p: &Path) -> String { p.to_string_lossy().replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase() }

impl Canon {
    fn path_reason(&self, p: &Path) -> Option<String> {
        // Split on both separators ourselves: on Linux a Windows path like D:\a\..\b
        // is a single component, so Path::components alone never sees the "..".
        if p.components().any(|c| matches!(c, Component::ParentDir)) || norm(p).split('\\').any(|c| c == "..") {
            return Some(format!("path traversal refused: {}", p.display()));
        }
        let s = norm(p);
        if let Some(d) = s.chars().next() {
            if s.get(1..2) == Some(":") && self.denied_drives.iter().any(|x| x.eq_ignore_ascii_case(&d)) {
                return Some(format!("drive {}: is off limits: {}", d.to_ascii_uppercase(), p.display()));
            }
        }
        let inside = self.roots.iter().map(|r| norm(r)).any(|r| s == r || s.starts_with(&format!("{r}\\")));
        if inside { None } else { Some(format!("outside allowed roots: {}", p.display())) }
    }

    pub fn check(&self, task: &Task, approvals: &[String]) -> Verdict {
        let mut need = Vec::new();
        for e in &task.effects {
            let token = match e {
                Effect::Read(p) | Effect::Write(p) => {
                    if let Some(r) = self.path_reason(p) { return Verdict::Deny(r); }
                    None
                }
                Effect::Delete(p) => {
                    if let Some(r) = self.path_reason(p) { return Verdict::Deny(r); }
                    Some(format!("delete:{}", norm(p)))
                }
                Effect::Commit => Some("commit".into()),
                Effect::Push => Some("push".into()),
                Effect::Send => Some("send".into()),
                Effect::Purchase => Some("purchase".into()),
                Effect::Network(h) => Some(format!("net:{}", h.to_ascii_lowercase())),
            };
            if let Some(t) = token {
                if !approvals.iter().any(|a| a.eq_ignore_ascii_case(&t)) && !need.contains(&t) { need.push(t); }
            }
        }
        if need.is_empty() { Verdict::Allow } else { Verdict::NeedsApproval(need) }
    }
}

/// Per (kind, tier) success history, from outcomes.jsonl.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outcome { pub task_id: String, pub kind: Kind, pub tier: Tier, pub ok: bool }

#[derive(Default)]
pub struct Stats { rows: Vec<Outcome> }

impl Stats {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let f = match std::fs::File::open(path) { Ok(f) => f, Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()), Err(e) => return Err(e) };
        // map_while, not filter_map: a read error from lines() repeats forever,
        // so filter_map would spin. Stop at the first I/O error instead.
        let rows = BufReader::new(f).lines().map_while(Result::ok).filter_map(|l| serde_json::from_str(&l).ok()).collect();
        Ok(Self { rows })
    }
    pub fn from_rows(rows: Vec<Outcome>) -> Self { Self { rows } }
    /// (failures, total) for the last 10 outcomes of this kind on this tier.
    pub fn recent(&self, kind: Kind, tier: Tier) -> (usize, usize) {
        let v: Vec<_> = self.rows.iter().rev().filter(|o| o.kind == kind && o.tier == tier).take(10).collect();
        (v.iter().filter(|o| !o.ok).count(), v.len())
    }
}

pub fn append_outcome(path: &Path, o: &Outcome) -> std::io::Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{}", serde_json::to_string(o).map_err(std::io::Error::other)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision { pub task_id: String, pub tier: Tier, pub reason: String, pub escalated: bool, pub verdict: Verdict }

/// Deterministic routing. No model chooses the tier, and none can skip the gate.
pub fn route(task: &Task, stats: &Stats) -> (Tier, String, bool) {
    let (base, why) = match task.kind {
        Kind::Quantum => return (Tier::TQuantum, "quantum work goes to LIMEN".into(), false),
        _ if task.private => return (Tier::T0Local, "private data pinned to local".into(), false),
        Kind::Classify | Kind::Chat if task.criticality <= 1 => (Tier::T0Local, "cheap, low criticality"),
        Kind::Research if task.criticality >= 2 => (Tier::T2Fleet, "broad research fans out"),
        _ => (Tier::T1Claude, "reasoning or code"),
    };
    let (fail, n) = stats.recent(task.kind, base);
    if n >= 3 && fail * 2 > n {
        let up = base.escalate();
        if up != base { return (up, format!("{why}; escalated, {fail}/{n} recent failures on {base:?}"), true); }
    }
    (base, why.into(), false)
}

pub fn sha256_json<T: Serialize>(v: &T) -> String {
    ductei_mcp::sha256_hex(serde_json::to_string(v).unwrap_or_default().as_bytes())
}

/// Decision plus the hash of the receipt that recorded it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decided { pub decision: Decision, pub receipt: String }

/// A router held open: canon, signer and receipt chain are loaded and
/// verified once, then every `decide` is gate + route + one receipt.
/// Long-lived callers (the MCP server) use this; the one-shot hook and CLI
/// go through [`decide`], which opens and drops one per call.
pub struct Router { state: PathBuf, canon: Canon, log: ductei_mcp::ReceiptLog }

impl Router {
    pub fn open(state: &Path) -> Result<Self, String> {
        let canon = Canon::load(state)?;
        let sign = load_sign(state)?;
        let log = ductei_mcp::ReceiptLog::open(state, &sign)?;
        Ok(Self { state: state.to_path_buf(), canon, log })
    }

    /// CANON gate -> tier -> chained (optionally signed) receipt. The receipt
    /// is written before the verdict is returned, so a denied or pending task
    /// is on the record whether or not the caller honours it.
    pub fn decide(&mut self, task: &Task, approvals: &[String]) -> Result<Decided, String> {
        let verdict = self.canon.check(task, approvals);
        // outcomes.jsonl is re-read per decision: `outcome` calls append to it
        // from other processes, and it is small (the rule reads the last 10 per kind/tier).
        let stats = Stats::load(&self.state.join("outcomes.jsonl")).map_err(|e| e.to_string())?;
        let (tier, reason, escalated) = route(task, &stats);
        let decision = Decision { task_id: task.id.clone(), tier, reason, escalated, verdict };
        let scope = format!("router:{}", serde_json::to_value(tier).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default());
        let body = ductei_mcp::ReceiptBody::new(task.id.clone(), scope, decision.verdict.label(), 0, 0, sha256_json(task), sha256_json(&decision));
        let r = self.log.record(body).map_err(|e| e.to_string())?;
        Ok(Decided { decision, receipt: r.hash })
    }

    pub fn receipts(&self) -> &ductei_mcp::ReceiptLog { &self.log }
}

/// One-shot decide: open the router, decide once, drop. Used by the hook and
/// the CLI, where the process lives for exactly one decision anyway.
pub fn decide(state: &Path, task: &Task, approvals: &[String]) -> Result<Decided, String> {
    Router::open(state)?.decide(task, approvals)
}

/// Exit code convention shared by the CLI and the hook.
pub fn exit_code(v: &Verdict) -> i32 {
    match v { Verdict::Allow => 0, Verdict::NeedsApproval(_) => 2, Verdict::Deny(_) => 3 }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn t(kind: Kind, effects: Vec<Effect>) -> Task { Task { id: "t".into(), intent: "x".into(), kind, criticality: 1, private: false, effects } }

    #[test] fn c_drive_denied() {
        let v = Canon::default().check(&t(Kind::Code, vec![Effect::Write(r"C:\Users\x\a.rs".into())]), &[]);
        assert!(matches!(v, Verdict::Deny(_)));
    }
    #[test] fn outside_roots_denied() {
        assert!(matches!(Canon::default().check(&t(Kind::Code, vec![Effect::Read(r"D:\LIMENX\a".into())]), &[]), Verdict::Deny(_)));
        assert!(matches!(Canon::default().check(&t(Kind::Code, vec![Effect::Read(r"D:\ATRIUM\..\secret".into())]), &[]), Verdict::Deny(_)));
    }
    #[test] fn inside_roots_allowed() {
        assert_eq!(Canon::default().check(&t(Kind::Code, vec![Effect::Write(r"d:/atrium/DUCTEI/x.rs".into())]), &[]), Verdict::Allow);
    }
    #[test] fn commit_needs_approval_then_passes() {
        let task = t(Kind::Code, vec![Effect::Commit, Effect::Push]);
        assert_eq!(Canon::default().check(&task, &[]), Verdict::NeedsApproval(vec!["commit".into(), "push".into()]));
        assert_eq!(Canon::default().check(&task, &["commit".into(), "PUSH".into()]), Verdict::Allow);
    }
    #[test] fn routing_rules() {
        let s = Stats::default();
        assert_eq!(route(&t(Kind::Quantum, vec![]), &s).0, Tier::TQuantum);
        let mut p = t(Kind::Research, vec![]); p.private = true; p.criticality = 3;
        assert_eq!(route(&p, &s).0, Tier::T0Local);
        assert_eq!(route(&t(Kind::Classify, vec![]), &s).0, Tier::T0Local);
        assert_eq!(route(&t(Kind::Code, vec![]), &s).0, Tier::T1Claude);
    }
    #[test] fn canon_file_cannot_unban_c_and_decide_chains() {
        let dir = std::env::temp_dir().join(format!("ductei-router-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir); std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("canon.toml"), "roots = ['D:\\ATRIUM', 'D:\\LIMEN']\ndenied_drives = ['E']\n").unwrap();
        let c = Canon::load(&dir).unwrap();
        assert!(c.denied_drives.contains(&'C') && c.denied_drives.contains(&'E'));
        assert_eq!(c.check(&t(Kind::Code, vec![Effect::Write(r"D:\LIMEN\a.py".into())]), &[]), Verdict::Allow);
        assert!(matches!(c.check(&t(Kind::Code, vec![Effect::Write(r"E:\a".into())]), &[]), Verdict::Deny(_)));
        std::fs::write(dir.join("canon.toml"), "roots = ['C:\\Users']\n").unwrap();
        assert!(Canon::load(&dir).is_err());
        std::fs::remove_file(dir.join("canon.toml")).unwrap();
        let a = decide(&dir, &t(Kind::Code, vec![]), &[]).unwrap();
        let b = decide(&dir, &t(Kind::Code, vec![Effect::Push]), &[]).unwrap();
        assert_eq!(a.decision.verdict, Verdict::Allow);
        assert!(matches!(b.decision.verdict, Verdict::NeedsApproval(_)));
        assert_ne!(a.receipt, b.receipt);
        let lines = std::fs::read_to_string(dir.join("receipts.jsonl")).unwrap();
        assert_eq!(lines.lines().count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test] fn held_open_router_matches_one_shot_and_shares_the_chain() {
        let dir = std::env::temp_dir().join(format!("ductei-router-open-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir); std::fs::create_dir_all(&dir).unwrap();
        let mut r = Router::open(&dir).unwrap();
        let a = r.decide(&t(Kind::Code, vec![]), &[]).unwrap();
        let b = r.decide(&t(Kind::Code, vec![Effect::Push]), &[]).unwrap();
        assert_eq!(r.receipts().seq, 2);
        assert_eq!(r.receipts().head, b.receipt);
        drop(r);
        // A one-shot decide extends the same chain, and a reopened router sees all three.
        let c = decide(&dir, &t(Kind::Chat, vec![]), &[]).unwrap();
        let r2 = Router::open(&dir).unwrap();
        assert_eq!((r2.receipts().seq, &r2.receipts().head), (3, &c.receipt));
        assert_ne!(a.receipt, c.receipt);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// cargo test -p ductei-router --release -- --ignored --nocapture bench_decide
    #[test] #[ignore] fn bench_decide_one_shot_vs_held_open() {
        let dir = std::env::temp_dir().join(format!("ductei-router-bench-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir); std::fs::create_dir_all(&dir).unwrap();
        let mut r = Router::open(&dir).unwrap();
        for _ in 0..5_000 { r.decide(&t(Kind::Code, vec![]), &[]).unwrap(); }
        let pct = |mut v: Vec<u128>, p: f64| { v.sort_unstable(); v[((v.len() - 1) as f64 * p) as usize] as f64 / 1000.0 };
        let held: Vec<u128> = (0..200).map(|_| { let s = std::time::Instant::now(); r.decide(&t(Kind::Code, vec![]), &[]).unwrap(); s.elapsed().as_micros() }).collect();
        drop(r);
        let shot: Vec<u128> = (0..200).map(|_| { let s = std::time::Instant::now(); decide(&dir, &t(Kind::Code, vec![]), &[]).unwrap(); s.elapsed().as_micros() }).collect();
        println!("chain of ~5400 receipts: one-shot decide p50 {:.3} ms p99 {:.3} ms | held-open p50 {:.3} ms p99 {:.3} ms",
            pct(shot.clone(), 0.5), pct(shot, 0.99), pct(held.clone(), 0.5), pct(held, 0.99));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test] fn escalates_on_failures() {
        let rows = (0..4).map(|i| Outcome { task_id: i.to_string(), kind: Kind::Classify, tier: Tier::T0Local, ok: i == 0 }).collect();
        let (tier, _, esc) = route(&t(Kind::Classify, vec![]), &Stats::from_rows(rows));
        assert_eq!((tier, esc), (Tier::T1Claude, true));
    }
}

pub mod mcp;
pub mod brain;
