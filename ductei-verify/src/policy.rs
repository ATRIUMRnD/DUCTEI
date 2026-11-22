//! Policy: loaded from TOML, validated against hard floors the file cannot loosen.

use crate::checks::norm;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub allowed_roots: Vec<String>,
    pub forbidden_prefixes: Vec<String>,
    pub ledger: String,
    pub limits: Limits,
    pub content: Content,
    pub commands: Commands,
    pub gates: Gates,
    pub breaker: Breaker,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_files: usize,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Content {
    pub allow_unsafe: bool,
    pub allow_deletions: bool,
    pub allow_test_removal: bool,
    pub forbid_patterns: Vec<String>,
    pub forbid_growth: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commands {
    pub forbid: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gates {
    pub require_check: bool,
    pub require_clippy: bool,
    pub require_tests: bool,
    pub min_tests_passed: u64,
    pub timeout_secs: u64,
    pub jlens_min: Option<f64>,
    pub eval_min_delta: f64,
    pub extra: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Breaker {
    pub max_attempts_per_task: u32,
    pub max_accepts_per_day: u32,
    pub kill_switch: String,
}

impl Policy {
    pub fn from_toml(s: &str) -> Result<Self, String> {
        let p: Policy = toml::from_str(s).map_err(|e| format!("policy: {e}"))?;
        p.validate()?;
        Ok(p)
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let s = std::fs::read_to_string(path).map_err(|e| format!("policy {path}: {e}"))?;
        Self::from_toml(&s)
    }

    /// Hard floors. A policy that breaks one is refused, so the loop cannot
    /// be loosened by editing the file.
    fn validate(&self) -> Result<(), String> {
        if self.allowed_roots.is_empty() {
            return Err("policy: allowed_roots is empty".into());
        }
        if self.allowed_roots.iter().any(|r| norm(r).starts_with("c:")) {
            return Err("policy: C: may not be an allowed root".into());
        }
        if !self.forbidden_prefixes.iter().any(|f| norm(f) == "c:") {
            return Err("policy: C:\\ must stay in forbidden_prefixes".into());
        }
        let forbid: Vec<String> = self.commands.forbid.iter().map(|c| c.to_ascii_lowercase()).collect();
        for must in ["git commit", "git push"] {
            if !forbid.iter().any(|c| c == must) {
                return Err(format!("policy: commands.forbid must include {must:?} (rule 1)"));
            }
        }
        if self.ledger.trim().is_empty() || self.breaker.kill_switch.trim().is_empty() {
            return Err("policy: ledger and kill_switch paths are required".into());
        }
        if !(1..=3600).contains(&self.gates.timeout_secs) {
            return Err("policy: timeout_secs must be 1..=3600".into());
        }
        if !self.gates.require_check && !self.gates.require_tests {
            return Err("policy: at least one of require_check / require_tests must be on".into());
        }
        if !self.gates.eval_min_delta.is_finite() || self.gates.eval_min_delta < 0.0 {
            return Err("policy: eval_min_delta must be finite and >= 0".into());
        }
        if self.gates.jlens_min.is_some_and(|m| !m.is_finite()) {
            return Err("policy: jlens_min must be finite".into());
        }
        if self.gates.extra.iter().any(|a| a.is_empty()) {
            return Err("policy: an extra gate has an empty argv".into());
        }
        let l = &self.limits;
        if l.max_files == 0 || l.max_file_bytes == 0 || l.max_total_bytes == 0 {
            return Err("policy: limits must be > 0".into());
        }
        if self.breaker.max_attempts_per_task == 0 || self.breaker.max_accepts_per_day == 0 {
            return Err("policy: breaker limits must be > 0".into());
        }
        Ok(())
    }
}
