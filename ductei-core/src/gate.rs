//! Build 0: causal-delta gate — pre-sync filter.
//! Rejects an envelope if its (lamport, node_id) is <= the last accepted
//! for the same (key, scope-set). Ties on lamport break deterministically
//! by node_id (higher node_id wins). Rejected deltas are logged (JSONL)
//! but never applied or re-broadcast.
//! Mirrors Qallow sync_wire semantics: same lamport + node_id fields the
//! versioned envelopes already carry; no wire change (oracle stays green).

use crate::Envelope;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict { Accept, Stale }

/// Key for gate state: (key, sorted scope set) — the same logical value
/// synced to different scope sets is tracked independently.
fn state_key(env: &Envelope) -> String {
    let mut s: Vec<&str> = env.scopes.iter().map(|x| x.0.as_str()).collect();
    s.sort_unstable();
    format!("{}\u{1f}{}", env.key, s.join("\u{1f}"))
}

#[derive(Default)]
pub struct CausalGate {
    last: HashMap<String, (u64, [u8; 16])>,
}
impl CausalGate {
    pub fn new() -> Self { Self::default() }
    pub fn admit(&mut self, env: &Envelope) -> Verdict {
        let k = state_key(env);
        match self.last.get(&k) {
            Some(&(l, n)) => {
                let newer = env.lamport > l || (env.lamport == l && env.node_id > n);
                if newer { self.last.insert(k, (env.lamport, env.node_id)); Verdict::Accept }
                else { Verdict::Stale }
            }
            None => { self.last.insert(k, (env.lamport, env.node_id)); Verdict::Accept }
        }
    }
}

/// Append-only JSONL log of rejected deltas (audit trail; never replayed
/// into state, never re-broadcast).
pub struct RejectLog { file: std::fs::File }
impl RejectLog {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        Ok(Self { file: OpenOptions::new().create(true).append(true).open(path)? })
    }
    pub fn record(&mut self, env: &Envelope) -> std::io::Result<()> {
        let line = serde_json::json!({
            "rejected": true,
            "key": env.key,
            "lamport": env.lamport,
            "node_id": env.node_id.to_vec(),
        });
        crate::write_line(&mut self.file, &line.to_string())?;
        self.file.sync_data()
    }
}
