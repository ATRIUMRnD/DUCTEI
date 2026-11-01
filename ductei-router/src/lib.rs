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

fn norm(p: &Path) -> String { p.to_string_lossy().replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase() }

impl Canon {
    fn path_reason(&self, p: &Path) -> Option<String> {
        if p.components().any(|c| matches!(c, Component::ParentDir)) {
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
        let rows = BufReader::new(f).lines().filter_map(|l| l.ok()).filter_map(|l| serde_json::from_str(&l).ok()).collect();
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
    #[test] fn escalates_on_failures() {
        let rows = (0..4).map(|i| Outcome { task_id: i.to_string(), kind: Kind::Classify, tier: Tier::T0Local, ok: i == 0 }).collect();
        let (tier, _, esc) = route(&t(Kind::Classify, vec![]), &Stats::from_rows(rows));
        assert_eq!((tier, esc), (Tier::T1Claude, true));
    }
}
