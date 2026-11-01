//! qhr-cell: the unit of work for the QHR (Quantum Hybrid Runtime) hyper
//! driver, written as plain Rust. The quantum words stay in this doc
//! comment; the API uses cells, branches, snapshots and commits.
//!
//! Mapping (metaphor -> mechanism):
//!   superposition  -> N branches of one cell run in parallel (qhr-sched)
//!   amplitude      -> branch weight, used only to order/prune branches
//!   measurement    -> the first branch whose output verifies is committed
//!   entanglement   -> a `Versioned<T>` commit fails if the snapshot it
//!                     was computed from is no longer current
//!   decoherence    -> a `Deadline`; a branch past it is dropped unread
//!   gate           -> a `Cell`: pure, deterministic, no I/O, budgeted
//!
//! Hard rules this crate enforces by construction:
//!   0. A cell never holds a lock. It receives a `Snapshot<T>` (an
//!      immutable `Arc<T>` plus the version it was taken at) and returns
//!      an owned output.
//!   1. A cell is deterministic given its input, so a committed branch can
//!      be replayed and re-hashed. The receipt hash chain in qhr-sched
//!      depends on this.
//!   2. Every cell has a budget (`Cell::budget`, default 1 ms). The
//!      scheduler measures real elapsed time per branch and reports
//!      overruns; the budget is a contract, not a hint.
//!   3. Nothing here owns durable state. Commits go through DUCTEI's
//!      channel (qhr-sched::commit); this crate only hashes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 32-byte digest, hex on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash(#[serde(with = "hex32")] pub [u8; 32]);

impl Hash {
    pub const ZERO: Hash = Hash([0u8; 32]);
    pub fn of(bytes: &[u8]) -> Hash {
        Hash(Sha256::digest(bytes).into())
    }
    /// Domain-separated hash of several parts (length-prefixed, so
    /// `("ab","c")` and `("a","bc")` never collide).
    pub fn chain(domain: &str, parts: &[&[u8]]) -> Hash {
        let mut h = Sha256::new();
        h.update(domain.as_bytes());
        h.update([0u8]);
        for p in parts {
            h.update((p.len() as u64).to_le_bytes());
            h.update(p);
        }
        Hash(h.finalize().into())
    }
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash({})", &self.to_hex()[..16])
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(d: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&d.iter().map(|b| format!("{b:02x}")).collect::<String>())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 64 {
            return Err(serde::de::Error::custom("hash must be 64 hex chars"));
        }
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(serde::de::Error::custom)?;
        }
        Ok(out)
    }
}

/// Clock abstraction so qhr can take its time base from universal-clock
/// later without changing cell code. The default is `std::time::Instant`
/// (monotonic, never goes backwards, which is the property deadlines need).
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MonotonicClock;
impl Clock for MonotonicClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// A point in time after which a branch is dropped unread.
#[derive(Debug, Clone, Copy)]
pub struct Deadline(pub Instant);
impl Deadline {
    pub fn after(clock: &dyn Clock, d: Duration) -> Deadline {
        Deadline(clock.now() + d)
    }
    pub fn expired(&self, clock: &dyn Clock) -> bool {
        clock.now() >= self.0
    }
    pub fn remaining(&self, clock: &dyn Clock) -> Duration {
        self.0.saturating_duration_since(clock.now())
    }
}

/// Immutable view of shared state at a known version. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Snapshot<T> {
    pub version: u64,
    pub value: Arc<T>,
}

/// Versioned shared state with optimistic commit. Readers never block
/// writers and writers never block readers for longer than an `Arc` swap.
/// A commit is accepted only if the caller computed from the current
/// version; otherwise it is `Stale` and the caller must re-read.
pub struct Versioned<T> {
    version: AtomicU64,
    value: Mutex<Arc<T>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CommitError {
    /// Snapshot version the branch computed from is no longer current.
    Stale { expected: u64, current: u64 },
}

impl<T> Versioned<T> {
    pub fn new(v: T) -> Self {
        Self {
            version: AtomicU64::new(0),
            value: Mutex::new(Arc::new(v)),
        }
    }
    pub fn snapshot(&self) -> Snapshot<T> {
        // Lock order: value then version read, so a concurrent commit is
        // either fully visible (new Arc, new version) or not at all.
        let g = self.value.lock().unwrap_or_else(|p| p.into_inner());
        let value = Arc::clone(&g);
        let version = self.version.load(Ordering::Acquire);
        Snapshot { version, value }
    }
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }
    /// Compare-and-swap commit keyed on the snapshot version.
    pub fn commit(&self, from: &Snapshot<T>, next: T) -> Result<u64, CommitError> {
        let mut g = self.value.lock().unwrap_or_else(|p| p.into_inner());
        let current = self.version.load(Ordering::Acquire);
        if current != from.version {
            return Err(CommitError::Stale {
                expected: from.version,
                current,
            });
        }
        *g = Arc::new(next);
        let v = current + 1;
        self.version.store(v, Ordering::Release);
        Ok(v)
    }
}

/// Cooperative cancellation handle given to every branch. A cell that
/// loops should poll `cancelled()` and return early; one that does not
/// loop can ignore it (its result is simply dropped on cancel).
#[derive(Debug, Clone, Default)]
pub struct Ctx {
    cancel: Arc<AtomicBool>,
}
impl Ctx {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed)
    }
}

/// A pocket-sized unit of work. Pure: no I/O, no locks, deterministic in
/// its input. `In` and `Out` must serialize so branches can be hashed and
/// replayed from the DUCTEI log.
pub trait Cell: Send + Sync {
    type In: Clone + Send + Sync + Serialize;
    type Out: Send + Serialize;

    /// Stable name, part of every receipt. Change it when semantics change.
    fn name(&self) -> &'static str;

    fn run(&self, ctx: &Ctx, input: &Self::In) -> Self::Out;

    /// Is this output acceptable to commit? Called on the scheduler thread
    /// after `run`. Default accepts everything; real cells override.
    fn verify(&self, _input: &Self::In, _out: &Self::Out) -> bool {
        true
    }

    /// Wall-clock budget for one `run`. The scheduler measures and reports
    /// overruns in the receipt; a hard cap belongs in the caller's
    /// `Deadline`. Default 1 ms.
    fn budget(&self) -> Duration {
        Duration::from_millis(1)
    }
}

/// Canonical hash of a serializable value (serde_json, which is
/// deterministic for the derive output used here: struct fields in
/// declaration order, maps only if BTreeMap).
pub fn hash_value<T: Serialize>(domain: &str, v: &T) -> Result<Hash, serde_json::Error> {
    let bytes = serde_json::to_vec(v)?;
    Ok(Hash::chain(domain, &[&bytes]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_chain_is_length_prefixed() {
        let a = Hash::chain("t", &[b"ab", b"c"]);
        let b = Hash::chain("t", &[b"a", b"bc"]);
        assert_ne!(a, b);
        assert_ne!(Hash::chain("t", &[b"x"]), Hash::chain("u", &[b"x"]));
    }

    #[test]
    fn hash_hex_roundtrip() {
        let h = Hash::of(b"hello");
        let s = serde_json::to_string(&h).unwrap();
        assert_eq!(s.len(), 66);
        let back: Hash = serde_json::from_str(&s).unwrap();
        assert_eq!(h, back);
        assert!(serde_json::from_str::<Hash>("\"abc\"").is_err());
    }

    #[test]
    fn versioned_commit_rejects_stale_snapshot() {
        let v = Versioned::new(1u32);
        let s0 = v.snapshot();
        let s1 = v.snapshot();
        assert_eq!(v.commit(&s0, 2), Ok(1));
        assert_eq!(
            v.commit(&s1, 3),
            Err(CommitError::Stale {
                expected: 0,
                current: 1
            })
        );
        assert_eq!(*v.snapshot().value, 2);
    }

    #[test]
    fn versioned_is_consistent_under_contention() {
        let v = Arc::new(Versioned::new(0u64));
        std::thread::scope(|s| {
            for _ in 0..8 {
                let v = Arc::clone(&v);
                s.spawn(move || {
                    for _ in 0..200 {
                        loop {
                            let snap = v.snapshot();
                            if v.commit(&snap, *snap.value + 1).is_ok() {
                                break;
                            }
                        }
                    }
                });
            }
        });
        assert_eq!(*v.snapshot().value, 1600);
        assert_eq!(v.version(), 1600);
    }

    #[test]
    fn deadline_expires() {
        let c = MonotonicClock;
        let d = Deadline::after(&c, Duration::from_millis(0));
        assert!(d.expired(&c));
        let d = Deadline::after(&c, Duration::from_secs(60));
        assert!(!d.expired(&c));
        assert!(d.remaining(&c) > Duration::from_secs(50));
    }
}
