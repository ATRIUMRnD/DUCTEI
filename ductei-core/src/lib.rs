//! ductei-core: scopes, envelopes, channel, persistence, bounded sessions,
//! causal-delta gate, TCP transport.
//! Design rules: deny-by-default scopes as first-class envelope fields;
//! channel-side append-only persistence (nothing acked before logged);
//! bounded sessions only; credentials unrepresentable by construction.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub mod gate;
#[cfg(feature = "net")]
pub mod transport;
#[cfg(feature = "grpc")]
pub mod grpc;
#[cfg(feature = "quic")]
pub mod quic;
/// Durable outbound intent/receipt log (separate from accepted log).
pub mod outbox;
/// Kani proof harnesses for the hard invariants (`cargo kani`); the same
/// bodies run as sampled tests under `cargo test` via `proof_shim.rs`.
#[cfg(any(kani, test))]
mod proofs;

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
        permits_with(&env.scopes, |s| self.allowed.contains(s))
    }
}

/// The deny-by-default rule itself, independent of how the allow-list is
/// stored. Split out of `ScopePolicy::permits` so it can be model-checked
/// without a `HashSet` (see proofs.rs). Generic over the scope type so the
/// proof can use plain numbers: the solver runs out of memory on heap strings.
fn permits_with<T>(scopes: &[T], allowed: impl Fn(&T) -> bool) -> bool {
    !scopes.is_empty() && scopes.iter().all(allowed)
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
        write_line(&mut self.file, &line)?;
        self.file.sync_data()
    }
    /// Writer-side repair, for the process that owns this log. If a crash left
    /// a half-written last line, end it with a newline so the next append
    /// starts a fresh line instead of being glued onto the fragment (which
    /// would lose both). Returns true if a repair was made.
    pub fn seal_torn_tail(&mut self) -> std::io::Result<bool> {
        let mut f = File::open(&self.path)?;
        if f.metadata()?.len() == 0 { return Ok(false); }
        f.seek(SeekFrom::End(-1))?;
        let mut last = [0u8; 1];
        f.read_exact(&mut last)?;
        if last[0] == b'\n' { return Ok(false); }
        self.file.write_all(b"\n")?;
        self.file.sync_data()?;
        Ok(true)
    }
    /// Replay from a line cursor. Returns (envelopes, next_cursor).
    ///
    /// Cost is the data appended since the last replay of this log in this
    /// process, not the size of the log: the end of each scan is remembered
    /// (see `marks`), so a poller calling `replay(cursor)` once a second on a
    /// log of any size reads only the new lines. A cursor below the remembered
    /// point (`replay(0)`) still scans from the start.
    ///
    /// Only whole lines count. A last line with no newline is one the writer
    /// has not finished (or a crash tore); it is left for the next replay
    /// instead of being counted and skipped for good.
    pub fn replay(&self, cursor: usize) -> std::io::Result<(Vec<Envelope>, usize)> {
        let mut f = File::open(&self.path)?;
        let len = f.metadata()?.len();
        let (mut n, mut off) = marks::resume(&self.path, cursor, len, &mut f).unwrap_or((0, 0));
        f.seek(SeekFrom::Start(off))?;
        let mut r = BufReader::new(f);
        let mut out = Vec::new();
        let mut buf = Vec::new();
        let mut guard = Vec::new();
        loop {
            buf.clear();
            let got = r.read_until(b'\n', &mut buf)?;
            if got == 0 || buf.last() != Some(&b'\n') { break; }
            off += got as u64;
            n += 1;
            if n > cursor {
                if let Ok(e) = serde_json::from_slice::<Envelope>(&buf) { out.push(e); }
            }
            guard.clear();
            guard.extend_from_slice(&buf[buf.len().saturating_sub(marks::GUARD)..]);
        }
        if !guard.is_empty() { marks::remember(&self.path, n, off, guard); }
        Ok((out, n))
    }
}

/// One whole line in one write call. `writeln!` on a `File` issues the text
/// and the newline as two writes, so a kill between them leaves a line with
/// no end and the next append is glued onto it.
pub fn write_line(w: &mut impl Write, line: &str) -> std::io::Result<()> {
    let mut b = Vec::with_capacity(line.len() + 1);
    b.extend_from_slice(line.as_bytes());
    b.push(b'\n');
    w.write_all(&b)
}

/// Where the last scan of each log ended, per process: (path, lines, byte
/// offset, the bytes just before that offset). The guard bytes are re-read
/// before a mark is used; if the file got shorter or those bytes changed
/// (the log was replaced, not appended to) the mark is dropped and the
/// replay scans from the start, so a stale mark can cost time, never
/// correctness.
mod marks {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    pub const GUARD: usize = 24;
    const KEEP: usize = 64;
    type Mark = (PathBuf, usize, u64, Vec<u8>);
    static MARKS: Mutex<Vec<Mark>> = Mutex::new(Vec::new());

    fn lock() -> std::sync::MutexGuard<'static, Vec<Mark>> {
        MARKS.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn resume(path: &Path, cursor: usize, len: u64, f: &mut File) -> Option<(usize, u64)> {
        let (lines, off, guard) = {
            let m = lock();
            let (_, lines, off, guard) = m.iter().find(|x| x.0 == path)?;
            (*lines, *off, guard.clone())
        };
        if lines > cursor { return None; }
        let same = off <= len && off >= guard.len() as u64 && {
            let mut got = vec![0u8; guard.len()];
            f.seek(SeekFrom::Start(off - guard.len() as u64)).is_ok() && f.read_exact(&mut got).is_ok() && got == guard
        };
        if !same {
            lock().retain(|x| x.0 != path);
            return None;
        }
        Some((lines, off))
    }

    pub fn remember(path: &Path, lines: usize, off: u64, guard: Vec<u8>) {
        let mut m = lock();
        m.retain(|x| x.0 != path);
        if m.len() >= KEEP { m.remove(0); }
        m.push((path.to_path_buf(), lines, off, guard));
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

/// Called once per envelope, only after it is accepted and fsynced to the
/// accepted log. The log stays the source of truth: an observer failure
/// never un-accepts an envelope, it is surfaced through `observer_faults`
/// so a sidecar (e.g. ductei-braid) can be resynced from the log.
pub type Observer = Box<dyn FnMut(&Envelope) -> Result<(), String> + Send>;

pub struct Channel {
    policy: ScopePolicy,
    log: LogStore,
    gate: gate::CausalGate,
    gate_log: gate::RejectLog,
    observers: Vec<Observer>,
    observer_faults: u64,
}
impl Channel {
    pub fn open(policy: ScopePolicy, log_path: impl AsRef<Path>, reject_log_path: impl AsRef<Path>) -> std::io::Result<Self> {
        let mut log = LogStore::open(&log_path)?;
        if log.seal_torn_tail()? {
            eprintln!("ductei: {} ended in a half-written line (crash mid-append); sealed it so new entries start clean", log_path.as_ref().display());
        }
        // Rebuild gate state from the accepted log so restarts stay consistent.
        let mut gate = gate::CausalGate::new();
        let (past, _) = log.replay(0)?;
        for e in &past { let _ = gate.admit(e); }
        Ok(Self {
            policy, log, gate,
            gate_log: gate::RejectLog::open(reject_log_path)?,
            observers: Vec::new(),
            observer_faults: 0,
        })
    }
    /// Register a post-accept observer (see `Observer`).
    pub fn observe(&mut self, o: Observer) { self.observers.push(o); }
    /// Number of observer calls that failed since open.
    pub fn observer_faults(&self) -> u64 { self.observer_faults }
    /// Scope check → causal gate → persist → observers. Only after the first
    /// three is the envelope "accepted" (and eligible for broadcast).
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
        self.log.append(&env).map_err(|e| ChannelError::Io(e.to_string()))?;
        for o in &mut self.observers {
            if let Err(e) = o(&env) {
                self.observer_faults += 1;
                eprintln!("ductei: observer failed for {}: {e}", env.key);
            }
        }
        Ok(())
    }
    pub fn replay(&self, cursor: usize) -> std::io::Result<(Vec<Envelope>, usize)> { self.log.replay(cursor) }
    pub fn session(&mut self, bound: SessionBound) -> Session<'_> {
        Session { ch: self, budget: SessionBudget::new(bound) }
    }
}

/// I/O-free session accounting, split out of `Session` so the
/// bounded-session invariant can be model-checked (see proofs.rs).
///
/// Overflow-safe by construction: a cost that would overflow the running
/// total is denied, never wrapped. (Before this split, `cost + spent`
/// wrapped in release builds, so a `u64::MAX` cost slipped past any
/// deadline and reset the reported total to 0.)
#[derive(Debug, Clone, Copy)]
struct SessionBudget {
    bound: SessionBound,
    sent: u32,
    cost: u64,
    closed: bool,
}
impl SessionBudget {
    fn new(bound: SessionBound) -> Self {
        Self { bound, sent: 0, cost: 0, closed: false }
    }
    /// May one more envelope of `cost` go out? A denial closes the budget
    /// for good.
    fn admit(&mut self, cost: u64) -> Result<(), ChannelError> {
        if self.closed { return Err(ChannelError::BoundReached); }
        if let Some(m) = self.bound.max_envelopes {
            if self.sent >= m { self.closed = true; return Err(ChannelError::BoundReached); }
        }
        if let Some(d) = self.bound.cost_deadline {
            match self.cost.checked_add(cost) {
                Some(total) if total <= d => {}
                _ => { self.closed = true; return Err(ChannelError::BoundReached); }
            }
        }
        Ok(())
    }
    /// Record a send the channel actually accepted. Saturating so a session
    /// with only one bound set can't panic or wrap on the other counter.
    fn commit(&mut self, cost: u64) {
        self.sent = self.sent.saturating_add(1);
        self.cost = self.cost.saturating_add(cost);
    }
}

pub struct Session<'a> {
    ch: &'a mut Channel,
    budget: SessionBudget,
}
impl<'a> Session<'a> {
    pub fn send(&mut self, env: Envelope, cost: u64) -> Result<(), ChannelError> {
        self.budget.admit(cost)?;
        self.ch.send(env)?;
        self.budget.commit(cost);
        Ok(())
    }
    pub fn is_closed(&self) -> bool { self.budget.closed }
    /// Orderly exit, idempotent, reports cost paid.
    pub fn close(&mut self) -> u64 { self.budget.closed = true; self.budget.cost }
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
