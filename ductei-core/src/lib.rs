//! ductei-core: scopes, envelopes, channel, persistence, bounded sessions,
//! causal-delta gate, TCP transport.
//! Design rules: deny-by-default scopes as first-class envelope fields;
//! channel-side append-only persistence (nothing acked before logged);
//! bounded sessions only; credentials unrepresentable by construction.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub mod gate;
#[cfg(feature = "net")]
pub mod transport;
#[cfg(feature = "grpc")]
pub mod grpc;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "pq")]
pub mod pq;
/// Durable outbound intent/receipt log (separate from accepted log).
pub mod outbox;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Scope(pub String);

/// Deny-by-default: only explicitly allowed scopes pass. One forbidden
/// scope poisons the whole envelope.
#[derive(Debug, Clone, Default)]
pub struct ScopePolicy {
    allowed: HashSet<Scope>,
}
impl ScopePolicy {
    pub fn new() -> Self { Self::default() }
    pub fn allow(mut self, s: &str) -> Self {
        self.allowed.insert(Scope(s.into()));
        self
    }
    pub fn permits(&self, env: &Envelope) -> bool {
        !env.scopes.is_empty() && env.scopes.iter().all(|s| self.allowed.contains(s))
    }
}

/// The one struct that crosses the channel. Scopes are first-class fields.
/// No credential fields exist; adapters use closed types so credentials
/// are unrepresentable before anything reaches here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub node_id: [u8; 16],
    pub lamport: u64,
    pub schema_ver: u16,
    pub flags: u16,
    pub key: String,
    pub scopes: Vec<Scope>,
    #[serde(with = "b64")]
    pub blob: Vec<u8>,
}

mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    pub fn enc(d: &[u8]) -> String {
        let mut o = String::new();
        for c in d.chunks(3) {
            let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            for i in 0..4 {
                if i <= c.len() { o.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char) } else { o.push('=') }
            }
        }
        o
    }
    pub fn dec(s: &str) -> Option<Vec<u8>> {
        let v: Vec<u8> = s.bytes().filter(|&b| b != b'=').map(|b| T.iter().position(|&t| t == b).map(|p| p as u8)).collect::<Option<_>>()?;
        let mut o = Vec::new();
        for c in v.chunks(4) {
            let mut n = 0u32;
            for (i, &x) in c.iter().enumerate() { n |= (x as u32) << (18 - 6 * i); }
            for i in 0..c.len() - 1 { o.push(((n >> (16 - 8 * i)) & 255) as u8); }
        }
        Some(o)
    }
    pub fn serialize<S: Serializer>(d: &[u8], s: S) -> Result<S::Ok, S::Error> { s.serialize_str(&enc(d)) }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        dec(&s).ok_or_else(|| serde::de::Error::custom("bad base64"))
    }
}

#[derive(Debug, PartialEq)]
pub enum ChannelError {
    ScopeDenied(String),
    BoundReached,
    Io(String),
    StaleDelta { key: String, lamport: u64 },
}

/// Append-only fsynced JSONL log with replay.
pub struct LogStore {
    path: PathBuf,
    file: File,
}
impl LogStore {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { path, file })
    }
    pub fn append(&mut self, env: &Envelope) -> std::io::Result<()> {
        let line = serde_json::to_string(env).map_err(std::io::Error::other)?;
        writeln!(self.file, "{line}")?;
        self.file.sync_data()
    }
    /// Replay from a line cursor. Returns (envelopes, next_cursor).
    pub fn replay(&self, cursor: usize) -> std::io::Result<(Vec<Envelope>, usize)> {
        let f = File::open(&self.path)?;
        let mut out = Vec::new();
        let mut n = 0usize;
        for (i, line) in BufReader::new(f).lines().enumerate() {
            let line = line?;
            n = i + 1;
            if i >= cursor {
                if let Ok(e) = serde_json::from_str::<Envelope>(&line) { out.push(e); }
            }
        }
        Ok((out, n))
    }
}

/// Bounded sessions: at least one bound (envelope budget / cost deadline)
/// is required at construction — a fully unbounded session is unrepresentable.
#[derive(Debug, Clone, Copy)]
pub struct SessionBound {
    pub max_envelopes: Option<u32>,
    pub cost_deadline: Option<u64>,
}
impl SessionBound {
    pub fn new(max_envelopes: Option<u32>, cost_deadline: Option<u64>) -> Option<Self> {
        if max_envelopes.is_none() && cost_deadline.is_none() { return None; }
        Some(Self { max_envelopes, cost_deadline })
    }
}

pub struct Channel {
    policy: ScopePolicy,
    log: LogStore,
    gate: gate::CausalGate,
    gate_log: gate::RejectLog,
}
impl Channel {
    pub fn open(policy: ScopePolicy, log_path: impl AsRef<Path>, reject_log_path: impl AsRef<Path>) -> std::io::Result<Self> {
        let log = LogStore::open(&log_path)?;
        // Rebuild gate state from the accepted log so restarts stay consistent.
        let mut gate = gate::CausalGate::new();
        let (past, _) = log.replay(0)?;
        for e in &past { let _ = gate.admit(e); }
        Ok(Self { policy, log, gate, gate_log: gate::RejectLog::open(reject_log_path)? })
    }
    /// Scope check → causal gate → persist. Only after all three is the
    /// envelope "accepted" (and eligible for broadcast).
    pub fn send(&mut self, env: Envelope) -> Result<(), ChannelError> {
        if !self.policy.permits(&env) {
            return Err(ChannelError::ScopeDenied(env.key));
        }
        match self.gate.admit(&env) {
            gate::Verdict::Accept => {}
            gate::Verdict::Stale => {
                self.gate_log.record(&env).map_err(|e| ChannelError::Io(e.to_string()))?;
                return Err(ChannelError::StaleDelta { key: env.key, lamport: env.lamport });
            }
        }
        self.log.append(&env).map_err(|e| ChannelError::Io(e.to_string()))
    }
    pub fn replay(&self, cursor: usize) -> std::io::Result<(Vec<Envelope>, usize)> { self.log.replay(cursor) }
    pub fn session(&mut self, bound: SessionBound) -> Session<'_> {
        Session { ch: self, bound, sent: 0, cost: 0, closed: false }
    }
}

pub struct Session<'a> {
    ch: &'a mut Channel,
    bound: SessionBound,
    sent: u32,
    cost: u64,
    closed: bool,
}
impl<'a> Session<'a> {
    pub fn send(&mut self, env: Envelope, cost: u64) -> Result<(), ChannelError> {
        if self.closed { return Err(ChannelError::BoundReached); }
        if let Some(m) = self.bound.max_envelopes {
            if self.sent >= m { self.closed = true; return Err(ChannelError::BoundReached); }
        }
        if let Some(d) = self.bound.cost_deadline {
            if self.cost + cost > d { self.closed = true; return Err(ChannelError::BoundReached); }
        }
        self.ch.send(env)?;
        self.sent += 1;
        self.cost += cost;
        Ok(())
    }
    pub fn is_closed(&self) -> bool { self.closed }
    /// Orderly exit, idempotent, reports cost paid.
    pub fn close(&mut self) -> u64 { self.closed = true; self.cost }
}

pub fn scoped(key: &str, scopes: &[&str], node: [u8; 16], lamport: u64, blob: &[u8]) -> Envelope {
    Envelope {
        node_id: node, lamport, schema_ver: 1, flags: 0,
        key: key.into(),
        scopes: scopes.iter().map(|s| Scope((*s).into())).collect(),
        blob: blob.to_vec(),
    }
}

pub type KeyState = HashMap<String, (u64, [u8; 16])>;
