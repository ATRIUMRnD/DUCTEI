//! ductei-mcp: put a DUCTEI channel between an MCP client and an MCP server.
//!
//! Every `tools/call` becomes a scoped Envelope (`mcp:{server}:{tool}`) that
//! must pass the deny-by-default ScopePolicy and land in the fsynced channel
//! log *before* it is forwarded; every result lands the same way *before* it
//! is returned. Each call/result pair then gets a hash-chained receipt
//! (optionally ML-DSA signed) in receipts.jsonl. Denied calls never reach
//! the server and are recorded in denied.jsonl plus a receipt with
//! verdict = "denied", so the timeline records refusals too.
//!
//! `tools/list` answers are filtered to the allowlist, so the client never
//! sees a tool it cannot call (and cannot burn the session budget on it).
//!
//! Receipt format v1: `v`, `kid` (SHA-256 of the signing public key, "" when
//! unsigned) and a domain-separated signature over the raw hash bytes. The
//! verifier takes its public key from the caller (pinned), not from the log
//! directory, so whoever can write the log directory cannot re-key history.
//!
//! Invariants carried over from ductei-core: deny-by-default scopes,
//! persistence-before-ack, bounded sessions, no credentials in envelopes
//! (the gate never sees the server's keys; it only relays JSON-RPC lines).
use ductei_core::{scoped, Channel, ChannelError, Envelope, LogStore, ScopePolicy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------- config

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerCfg,
    pub policy: PolicyCfg,
    #[serde(default)]
    pub log: LogCfg,
    #[serde(default)]
    pub sign: SignCfg,
    #[serde(default)]
    pub anchor: AnchorCfg,
}

/// Chain-head anchoring: every N receipts the gate signs `(seq, head)` and
/// pushes it to DUCTEI peers over TCP. A peer that holds a later anchor than
/// the local receipts.jsonl shows is proof the local file was truncated.
#[derive(Debug, Deserialize, Clone)]
pub struct AnchorCfg {
    /// Anchor every N receipts. 0 = off.
    #[serde(default)]
    pub every: u64,
    /// DUCTEI TCP peers (host:port). Each must allow scope `mcp:{server}:anchor`.
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Peers must resolve to tailnet or loopback addresses unless this is true.
    #[serde(default)]
    pub allow_public_peers: bool,
    /// Push anchors over the QFLTL-encrypted, mutually authenticated transport
    /// (needs the `qfltl` feature). Each peer must be pinned under
    /// `<log dir>/anchor-state/qfltl/known_servers/<peer>.pub`, and the peer must
    /// pin this gate's `<log dir>/anchor-state/qfltl/identity.pub` as a client.
    /// When true there is never a plaintext fallback.
    #[serde(default)]
    pub encrypt: bool,
}
fn default_connect_timeout_ms() -> u64 { 2000 }
impl Default for AnchorCfg {
    fn default() -> Self { Self { every: 0, peers: vec![], connect_timeout_ms: default_connect_timeout_ms(), allow_public_peers: false, encrypt: false } }
}

#[derive(Debug, Deserialize)]
pub struct ServerCfg {
    /// Short name used in scopes and keys, e.g. "gev" or "video-watch".
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyCfg {
    /// Tool names allowed through. Deny-by-default: an empty list blocks every call.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Bounded session: calls (accepted or denied) per gate process lifetime.
    pub max_calls_per_session: u32,
    /// Client methods allowed besides initialize, ping, tools/list, tools/call
    /// and notifications/*, e.g. ["resources/list", "resources/read"]. Default: none.
    #[serde(default)]
    pub allow_methods: Vec<String>,
    /// Requests the server may make of the client, e.g. "sampling/createMessage",
    /// "elicitation/create", "roots/list". Default: none. Server notifications always pass.
    #[serde(default)]
    pub allow_server_methods: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct LogCfg {
    /// Directory for channel.jsonl, denied.jsonl, rejected.jsonl, receipts.jsonl,
    /// gate-node-id and the signing key. Default: ./ductei next to the config.
    pub dir: Option<PathBuf>,
    /// Windows: on every start, reset the dir's ACL to this user + SYSTEM only.
    #[serde(default = "yes")]
    pub restrict_acl: bool,
    /// Receipt durability. 1 (default) = fsync every receipt (the verified
    /// tier). N > 1 = fast lane: fsync every N receipts or when `sync_max_ms`
    /// has passed since the last fsync, whichever comes first, plus always at
    /// exit. Receipts are still hash-chained and signed one by one; only the
    /// crash-loss window changes (at most the last N unsynced receipts), and
    /// a truncated tail is still caught by anchors.
    #[serde(default = "one")]
    pub sync_every: u64,
    /// Fast lane only: upper bound in ms between fsyncs while receipts flow.
    /// 0 = count-only. Checked at the next record, so an idle tail waits for
    /// exit or the next receipt.
    #[serde(default)]
    pub sync_max_ms: u64,
    /// Fast lane only: fsync on a background thread every `sync_max_ms`
    /// (10 ms when unset) so `record` never waits on the disk, except as
    /// backpressure when `sync_every` receipts are pending. A failed
    /// background fsync stops the gate (fail closed). Ignored when
    /// `sync_every` = 1.
    #[serde(default)]
    pub sync_background: bool,
}
fn yes() -> bool { true }
fn one() -> u64 { 1 }

#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    #[default]
    #[serde(rename = "none")]
    None,
    #[serde(rename = "ml-dsa-65")]
    MlDsa65,
    /// CNSA 2.0 parameter set.
    #[serde(rename = "ml-dsa-87")]
    MlDsa87,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::None => "none",
            Scheme::MlDsa65 => "ml-dsa-65",
            Scheme::MlDsa87 => "ml-dsa-87",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Scheme::None),
            "ml-dsa-65" => Some(Scheme::MlDsa65),
            "ml-dsa-87" => Some(Scheme::MlDsa87),
            _ => None,
        }
    }
}

/// Where the secret key lives at rest.
#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
pub enum KeyStore {
    /// DPAPI on Windows; plaintext elsewhere (and only with `insecure_plaintext_key = true`).
    #[default]
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "dpapi")]
    Dpapi,
    #[serde(rename = "plaintext")]
    Plaintext,
}

#[derive(Debug, Deserialize, Default)]
pub struct SignCfg {
    #[serde(default)]
    pub scheme: Scheme,
    #[serde(default)]
    pub key_store: KeyStore,
    /// SHA-256 hex of the public key this gate must sign with. If set and the
    /// key on disk does not match, the gate refuses to start.
    #[serde(default)]
    pub pubkey_fingerprint: Option<String>,
    /// Must be true to store the secret key as a plaintext file.
    #[serde(default)]
    pub insecure_plaintext_key: bool,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
    }
    pub fn log_dir(&self, config_path: &Path) -> PathBuf {
        self.log.dir.clone().unwrap_or_else(|| {
            config_path.parent().unwrap_or(Path::new(".")).join("ductei")
        })
    }
}

impl Default for LogCfg {
    fn default() -> Self { Self { dir: None, restrict_acl: true, sync_every: 1, sync_max_ms: 0, sync_background: false } }
}

pub fn scope_for(server: &str, tool: &str) -> String {
    format!("mcp:{server}:{tool}")
}

// ---------------------------------------------------------------- hex / hash

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    to_hex(&Sha256::digest(data))
}

// ---------------------------------------------------------------- node id

/// Same persisted-identity rule as ductei-limen-relay: one id per install,
/// so the causal gate sees one producer across restarts.
pub fn load_or_create_node_id(dir: &Path) -> std::io::Result<[u8; 16]> {
    let path = dir.join("gate-node-id");
    if let Ok(s) = fs::read_to_string(&path) {
        if let Some(v) = from_hex(s.trim()) {
            if v.len() == 16 {
                let mut id = [0u8; 16];
                id.copy_from_slice(&v);
                return Ok(id);
            }
        }
    }
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).map_err(|e| std::io::Error::other(e.to_string()))?;
    fs::write(&path, to_hex(&id))?;
    Ok(id)
}

// ---------------------------------------------------------------- receipts

pub const RECEIPT_VERSION: u32 = 1;
/// Domain separator prepended to the raw hash bytes before signing, so a
/// receipt signature can never be replayed as a signature over some other
/// DUCTEI object that happens to share the hash.
pub const SIGN_DOMAIN: &[u8] = b"ductei-mcp-receipt-v1\0";

/// The fields that are hashed and signed, in this exact order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReceiptBody {
    pub v: u32,
    pub seq: u64,
    pub prev: String,
    /// SHA-256 hex of the signing public key; "" when scheme = none.
    pub kid: String,
    pub key: String,
    pub scope: String,
    pub verdict: String,
    pub lamport_call: u64,
    pub lamport_result: u64,
    pub call_sha256: String,
    pub result_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    #[serde(flatten)]
    pub body: ReceiptBody,
    pub hash: String,
    pub scheme: String,
    pub sig: Option<String>,
}

impl ReceiptBody {
    /// Unfilled template: `seq`, `prev`, `kid` and `v` are set by `ReceiptLog::record`.
    pub fn new(key: String, scope: String, verdict: &str, lamport_call: u64, lamport_result: u64, call_sha256: String, result_sha256: String) -> Self {
        Self { v: RECEIPT_VERSION, seq: 0, prev: String::new(), kid: String::new(), key, scope, verdict: verdict.into(), lamport_call, lamport_result, call_sha256, result_sha256 }
    }
    pub fn hash(&self) -> String {
        // serde_json preserves struct field order, so this is canonical for us.
        sha256_hex(serde_json::to_string(self).expect("receipt body serializes").as_bytes())
    }
}

/// What actually gets signed: domain || raw 32-byte hash.
pub fn signing_message(hash_hex: &str) -> Vec<u8> {
    let mut m = SIGN_DOMAIN.to_vec();
    m.extend(from_hex(hash_hex).unwrap_or_default());
    m
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// When receipts.jsonl is fsynced. See `LogCfg::sync_every`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Durability {
    pub sync_every: u64,
    pub sync_max_ms: u64,
    /// fsync on a background thread every `sync_max_ms`; `record` never
    /// fsyncs inline unless `sync_every` receipts are pending (backpressure).
    pub background: bool,
}
impl Default for Durability {
    fn default() -> Self { Self { sync_every: 1, sync_max_ms: 0, background: false } }
}
/// Background flush interval when `background` is set but no interval is.
pub const DEFAULT_BACKGROUND_SYNC_MS: u64 = 10;
impl Durability {
    pub fn from_log(cfg: &LogCfg) -> Self {
        let background = cfg.sync_background && cfg.sync_every > 1;
        let sync_max_ms = if background && cfg.sync_max_ms == 0 { DEFAULT_BACKGROUND_SYNC_MS } else { cfg.sync_max_ms };
        Self { sync_every: cfg.sync_every.max(1), sync_max_ms, background }
    }
}

/// The background fsync thread of a `ReceiptLog`, stopped and joined on drop.
struct Flusher { stop: std::sync::Arc<std::sync::atomic::AtomicBool>, handle: Option<std::thread::JoinHandle<()>> }

/// Append-only receipts.jsonl with an in-memory chain head.
pub struct ReceiptLog {
    file: File,
    pub seq: u64,
    pub head: String,
    pub signer: Signer,
    durability: Durability,
    /// Receipts written / known durable since open. Shared with the flusher.
    written: std::sync::Arc<std::sync::atomic::AtomicU64>,
    synced: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// fsyncs performed, inline and background (observable in tests and the exit line).
    syncs: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Set by the flusher when an fsync fails; the next record/flush fails closed.
    bg_failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    last_sync: std::time::Instant,
    flusher: Option<Flusher>,
}

impl ReceiptLog {
    pub fn open(dir: &Path, sign: &SignCfg) -> Result<Self, String> {
        Self::open_with(dir, sign, Durability::default())
    }

    pub fn open_with(dir: &Path, sign: &SignCfg, durability: Durability) -> Result<Self, String> {
        Self::open_in(dir, dir, sign, durability)
    }

    /// Receipts in `dir`, signing key in `key_dir`. Lets several chains share
    /// one key (one fingerprint to pin), as QHR does with verified/ and fast/.
    pub fn open_in(dir: &Path, key_dir: &Path, sign: &SignCfg, durability: Durability) -> Result<Self, String> {
        let path = dir.join("receipts.jsonl");
        let (seq, head) = match File::open(&path) {
            Ok(f) => {
                // Refuse to extend a chain that is already damaged (torn write,
                // edit, foreign lines): appending would bury the break.
                let mut seq = 0u64;
                let mut head = GENESIS.to_string();
                let refuse = |n: usize, why: String| format!("{}: line {n}: {why}; refusing to extend a damaged chain. Run `ductei-mcp-gate verify`, then move the file aside to start a new chain", path.display());
                for (i, line) in BufReader::new(f).lines().enumerate() {
                    let line = line.map_err(|e| e.to_string())?;
                    let r: Receipt = serde_json::from_str(&line).map_err(|e| refuse(i + 1, format!("unparsable ({e})")))?;
                    if r.body.seq != seq || r.body.prev != head || r.body.hash() != r.hash {
                        return Err(refuse(i + 1, "chain broken".into()));
                    }
                    seq += 1;
                    head = r.hash;
                }
                (seq, head)
            }
            Err(_) => (0, GENESIS.to_string()),
        };
        let file = OpenOptions::new().create(true).append(true).open(&path).map_err(|e| e.to_string())?;
        let signer = Signer::load_or_create(key_dir, sign)?;
        use std::sync::{atomic::{AtomicBool, AtomicU64}, Arc};
        let written = Arc::new(AtomicU64::new(0));
        let synced = Arc::new(AtomicU64::new(0));
        let syncs = Arc::new(AtomicU64::new(0));
        let bg_failed = Arc::new(AtomicBool::new(false));
        let flusher = if durability.background {
            let f = file.try_clone().map_err(|e| format!("{}: clone for background fsync: {e}", path.display()))?;
            Some(spawn_flusher(f, durability.sync_max_ms.max(1), written.clone(), synced.clone(), syncs.clone(), bg_failed.clone())?)
        } else { None };
        Ok(Self { file, seq, head, signer, durability, written, synced, syncs, bg_failed, last_sync: std::time::Instant::now(), flusher })
    }

    pub fn durability(&self) -> Durability { self.durability }

    /// Receipts written but not yet fsynced (0 in the verified tier).
    pub fn unsynced(&self) -> u64 {
        use std::sync::atomic::Ordering::Acquire;
        self.written.load(Acquire).saturating_sub(self.synced.load(Acquire))
    }

    /// fsyncs performed so far, inline and background.
    pub fn syncs(&self) -> u64 { self.syncs.load(std::sync::atomic::Ordering::Acquire) }

    fn check_background(&self) -> std::io::Result<()> {
        if self.bg_failed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(std::io::Error::other("background fsync of receipts.jsonl failed; refusing to continue unsynced"));
        }
        Ok(())
    }

    pub fn record(&mut self, mut body: ReceiptBody) -> std::io::Result<Receipt> {
        self.check_background()?;
        body.v = RECEIPT_VERSION;
        body.seq = self.seq;
        body.prev = self.head.clone();
        body.kid = self.signer.kid.clone();
        let hash = body.hash();
        let sig = self.signer.sign(&signing_message(&hash));
        let r = Receipt { body, hash: hash.clone(), scheme: self.signer.scheme.as_str().into(), sig };
        writeln!(self.file, "{}", serde_json::to_string(&r)?)?;
        // Count only after the line is written, so the flusher never claims
        // durability for a line that is not in the file yet.
        self.written.fetch_add(1, std::sync::atomic::Ordering::Release);
        let d = self.durability;
        let due_by_count = self.unsynced() >= d.sync_every;
        let due_by_time = !d.background && d.sync_max_ms > 0 && self.last_sync.elapsed().as_millis() as u64 >= d.sync_max_ms;
        if due_by_count || due_by_time {
            self.flush()?;
        }
        // The chain head advances only after the line is written; on a failed
        // fsync the error surfaces to the caller and the head stays behind.
        self.seq += 1;
        self.head = hash;
        Ok(r)
    }

    /// fsync anything not yet synced. No-op when nothing is pending. Called
    /// before every anchor and at every exit path of the gate.
    pub fn flush(&mut self) -> std::io::Result<()> {
        use std::sync::atomic::Ordering::{AcqRel, Acquire};
        self.check_background()?;
        let w = self.written.load(Acquire);
        if w <= self.synced.load(Acquire) { return Ok(()); }
        self.file.sync_data()?;
        self.synced.fetch_max(w, AcqRel);
        self.syncs.fetch_add(1, AcqRel);
        self.last_sync = std::time::Instant::now();
        Ok(())
    }
}

fn spawn_flusher(
    file: File,
    every_ms: u64,
    written: std::sync::Arc<std::sync::atomic::AtomicU64>,
    synced: std::sync::Arc<std::sync::atomic::AtomicU64>,
    syncs: std::sync::Arc<std::sync::atomic::AtomicU64>,
    failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<Flusher, String> {
    use std::sync::atomic::{AtomicBool, Ordering::{AcqRel, Acquire, Release}};
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    let interval = std::time::Duration::from_millis(every_ms);
    let handle = std::thread::Builder::new().name("receipts-fsync".into()).spawn(move || {
        while !s.load(Acquire) {
            std::thread::park_timeout(interval);
            // Read the count first: every line it covers is already in the file.
            let w = written.load(Acquire);
            if w > synced.load(Acquire) {
                match file.sync_data() {
                    Ok(()) => { synced.fetch_max(w, AcqRel); syncs.fetch_add(1, AcqRel); }
                    Err(e) => { eprintln!("ductei-mcp: background fsync failed: {e}"); failed.store(true, Release); return; }
                }
            }
        }
    }).map_err(|e| format!("spawn background fsync: {e}"))?;
    Ok(Flusher { stop, handle: Some(handle) })
}

impl Drop for ReceiptLog {
    fn drop(&mut self) {
        if let Some(mut f) = self.flusher.take() {
            f.stop.store(true, std::sync::atomic::Ordering::Release);
            if let Some(h) = f.handle.take() { h.thread().unpark(); let _ = h.join(); }
        }
        // Best effort: whatever is still pending goes to disk on the way out.
        let _ = self.flush();
    }
}

// ---------------------------------------------------------------- anchors

pub const ANCHOR_DOMAIN: &[u8] = b"ductei-mcp-anchor-v1\0";

/// A signed statement "receipt `seq` has hash `head`". Lives outside the
/// log dir (on a peer) so a shortened receipts.jsonl can be caught.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Anchor {
    pub v: u32,
    pub kid: String,
    pub seq: u64,
    pub head: String,
    pub scheme: String,
    pub sig: Option<String>,
}

pub fn anchor_message(seq: u64, head: &str) -> Vec<u8> {
    let mut m = ANCHOR_DOMAIN.to_vec();
    m.extend(seq.to_le_bytes());
    m.extend(from_hex(head).unwrap_or_default());
    m
}

pub fn anchor_scope(server: &str) -> String { format!("mcp:{server}:anchor") }

impl ReceiptLog {
    /// Anchor for the last receipt written. None if nothing was written yet.
    pub fn anchor(&self) -> Option<Anchor> {
        if self.seq == 0 { return None; }
        let seq = self.seq - 1;
        let sig = self.signer.sign(&anchor_message(seq, &self.head));
        Some(Anchor { v: RECEIPT_VERSION, kid: self.signer.kid.clone(), seq, head: self.head.clone(), scheme: self.signer.scheme.as_str().into(), sig })
    }
}

impl Anchor {
    /// Signature check against a trusted key. Unsigned anchors (scheme none)
    /// are accepted only when `pk` is None, i.e. the log is unsigned too.
    pub fn verify(&self, pk: Option<&(Scheme, Vec<u8>)>) -> bool {
        match (pk, &self.sig) {
            (Some((scheme, pkb)), Some(sig)) => scheme.as_str() == self.scheme && self.kid == sha256_hex(pkb) && Signer::verify(*scheme, pkb, &anchor_message(self.seq, &self.head), sig),
            (None, None) => self.scheme == "none",
            _ => false,
        }
    }
}

/// Push one envelope to a DUCTEI TCP peer with timeouts and record intent and
/// ack in an outbox. Same frame format as ductei-core transport
/// (u32 LE length + JSON, 1 ack byte: 1 applied, 2 stale, 0 rejected).
pub fn push_envelope(peer: &str, env: &Envelope, timeout: std::time::Duration, outbox: &Path, allow_public: bool) -> Result<u8, String> {
    use std::io::Read;
    use std::net::{TcpStream, ToSocketAddrs};
    let addr = peer.to_socket_addrs().map_err(|e| format!("{peer}: {e}"))?.next().ok_or_else(|| format!("{peer}: no address"))?;
    if !allow_public && !peer_allowed(&addr) {
        return Err(format!("{peer} resolves to {addr}, not a tailnet or loopback address (set anchor.allow_public_peers to override)"));
    }
    let mut ob = ductei_core::outbox::Outbox::open(outbox).map_err(|e| e.to_string())?;
    ob.record_intent(env).map_err(|e| e.to_string())?;
    let mut s = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("{peer}: connect: {e}"))?;
    s.set_read_timeout(Some(timeout)).ok();
    s.set_write_timeout(Some(timeout)).ok();
    let body = serde_json::to_vec(env).map_err(|e| e.to_string())?;
    s.write_all(&(body.len() as u32).to_le_bytes()).and_then(|_| s.write_all(&body)).and_then(|_| s.flush()).map_err(|e| format!("{peer}: write: {e}"))?;
    let mut ack = [0u8; 1];
    if let Err(e) = s.read_exact(&mut ack) {
        let _ = ob.record_receipt(&env.key, env.lamport, &env.node_id, 0xFF);
        return Err(format!("{peer}: no ack: {e}"));
    }
    ob.record_receipt(&env.key, env.lamport, &env.node_id, ack[0]).map_err(|e| e.to_string())?;
    Ok(ack[0])
}

/// QFLTL-encrypted twin of [`push_envelope`]: same frame, same ack, same outbox
/// bookkeeping, but over the mutually authenticated v3 handshake from
/// ductei-sync. `state_root` holds this gate's identity and the pinned server
/// keys (`<state_root>/qfltl/...`). A peer with no pinned key is refused before
/// any byte is sent, and a failed handshake sends nothing.
#[cfg(feature = "qfltl")]
pub fn push_envelope_qfltl(state_root: &Path, peer: &str, env: &Envelope, timeout: std::time::Duration, outbox: &Path, allow_public: bool) -> Result<u8, String> {
    use ductei_sync::qfltl_transport::{client_handshake, load_or_generate_identity, pinned_server_key};
    use std::io::Read;
    use std::net::{TcpStream, ToSocketAddrs};
    let addr = peer.to_socket_addrs().map_err(|e| format!("{peer}: {e}"))?.next().ok_or_else(|| format!("{peer}: no address"))?;
    if !allow_public && !peer_allowed(&addr) {
        return Err(format!("{peer} resolves to {addr}, not a tailnet or loopback address (set anchor.allow_public_peers to override)"));
    }
    let pin = pinned_server_key(state_root, peer)
        .map_err(|e| format!("{peer}: read pin: {e}"))?
        .ok_or_else(|| format!("{peer}: no pinned server key under {}/qfltl/known_servers; refusing to send", state_root.display()))?;
    let identity = load_or_generate_identity(state_root).map_err(|e| format!("{peer}: identity: {e}"))?;
    let mut ob = ductei_core::outbox::Outbox::open(outbox).map_err(|e| e.to_string())?;
    ob.record_intent(env).map_err(|e| e.to_string())?;
    let tcp = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("{peer}: connect: {e}"))?;
    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(timeout)).ok();
    let mut s = client_handshake(tcp, &identity, &pin).map_err(|e| format!("{peer}: handshake: {e}"))?;
    let body = serde_json::to_vec(env).map_err(|e| e.to_string())?;
    s.write_all(&(body.len() as u32).to_le_bytes()).and_then(|_| s.write_all(&body)).and_then(|_| s.flush()).map_err(|e| format!("{peer}: write: {e}"))?;
    let mut ack = [0u8; 1];
    if let Err(e) = s.read_exact(&mut ack) {
        let _ = ob.record_receipt(&env.key, env.lamport, &env.node_id, 0xFF);
        return Err(format!("{peer}: no ack: {e}"));
    }
    ob.record_receipt(&env.key, env.lamport, &env.node_id, ack[0]).map_err(|e| e.to_string())?;
    Ok(ack[0])
}

/// Push one anchor the way the config says. With `anchor.encrypt` it uses the
/// QFLTL transport and never falls back to plaintext; if this build lacks the
/// `qfltl` feature that is an error, not a downgrade.
pub fn push_anchor(cfg: &AnchorCfg, state_root: &Path, peer: &str, env: &Envelope, outbox: &Path) -> Result<u8, String> {
    let timeout = std::time::Duration::from_millis(cfg.connect_timeout_ms);
    if cfg.encrypt {
        #[cfg(feature = "qfltl")]
        return push_envelope_qfltl(state_root, peer, env, timeout, outbox, cfg.allow_public_peers);
        #[cfg(not(feature = "qfltl"))]
        {
            let _ = state_root;
            return Err("anchor.encrypt is set but this build has no `qfltl` feature; refusing plaintext".into());
        }
    }
    push_envelope(peer, env, timeout, outbox, cfg.allow_public_peers)
}
/// Anchors found in a peer's exported log (channel.jsonl) or a local
/// anchors.jsonl: every envelope whose blob parses as an Anchor.
pub fn anchors_in(path: &Path) -> Result<Vec<Anchor>, String> {
    let store = LogStore::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let (envs, _) = store.replay(0).map_err(|e| e.to_string())?;
    Ok(envs.iter().filter_map(|e| serde_json::from_slice::<Anchor>(&e.blob).ok()).collect())
}

// ---------------------------------------------------------------- verify

/// What the verifier is told to trust. Nothing in the log directory is
/// trusted by default: a writer there could have re-keyed the whole chain.
#[derive(Debug, Default)]
pub struct VerifyTrust {
    /// Raw public key bytes supplied out-of-band (`--pubkey <file>`).
    pub pubkey: Option<Vec<u8>>,
    /// SHA-256 hex the public key must match (`--fingerprint <hex>`).
    pub fingerprint: Option<String>,
    /// Accept the `.pk` found in the log dir with no pin. Verification then
    /// proves integrity and ordering, not authorship.
    pub allow_unpinned: bool,
    /// Anchors obtained from outside the log dir (a peer's channel.jsonl
    /// export, or `seq:hash` typed by hand). The highest valid one must be
    /// present in receipts.jsonl, which catches tail truncation.
    pub anchors: Vec<Anchor>,
    /// `(seq, hash)` the operator copied by hand (`--anchor seq:hash`). Trusted
    /// as-is, since it came from the operator, not from a file.
    pub pinned_head: Option<(u64, String)>,
}

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub receipts: u64,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    /// Fingerprint of the key the receipts were checked against, if any.
    pub kid: Option<String>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool { self.errors.is_empty() }
}

fn blob_hashes(path: &Path, flags: u16) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(store) = LogStore::open(path) {
        if let Ok((envs, _)) = store.replay(0) {
            for e in envs.iter().filter(|e| e.flags == flags) { set.insert(sha256_hex(&e.blob)); }
        }
    }
    set
}

/// Blob hashes keyed by Lamport stamp. A receipt names the exact channel
/// entries it covers (`lamport_call`, `lamport_result`); checking by position
/// catches deletion of an entry whose content repeats elsewhere, which a plain
/// hash set cannot (a polling client repeats the same call thousands of times).
fn blob_index(path: &Path, flags: u16) -> HashMap<u64, Vec<String>> {
    let mut map: HashMap<u64, Vec<String>> = HashMap::new();
    if let Ok(store) = LogStore::open(path) {
        if let Ok((envs, _)) = store.replay(0) {
            for e in envs.iter().filter(|e| e.flags == flags) { map.entry(e.lamport).or_default().push(sha256_hex(&e.blob)); }
        }
    }
    map
}

/// Recompute the chain, every signature, the key pin, and cross-check each
/// receipt's hashes against the channel / denied logs (the gate's receipts).
pub fn verify_receipts(dir: &Path, trust: &VerifyTrust) -> Result<VerifyReport, String> {
    // Read order matters on a live gate. The gate persists to channel.jsonl
    // before it writes the receipt, so: count receipts first, read the channel
    // second, and cross-check only receipts that existed before the channel
    // snapshot. Later receipts still get the chain/signature checks; they are
    // cross-checked on the next run. Reading channel first made a call landing
    // between the two reads look like a missing result (seen live, Nov 1 2026).
    let snapshot = File::open(dir.join("receipts.jsonl")).map(|f| BufReader::new(f).lines().count() as u64).unwrap_or(0);
    let calls = blob_index(&dir.join("channel.jsonl"), 0);
    let results = blob_index(&dir.join("channel.jsonl"), 1);
    let at = |m: &HashMap<u64, Vec<String>>, l: u64, h: &str| m.get(&l).is_some_and(|v| v.iter().any(|x| x == h));
    let denied = blob_hashes(&dir.join("denied.jsonl"), 0);
    let sessions = blob_hashes(&dir.join("sessions.jsonl"), 0);
    verify_chain(dir, trust, |r, rep| {
        let s = r.body.seq;
        if s >= snapshot { return; }
        match r.body.verdict.as_str() {
            "accepted" => {
                if !at(&calls, r.body.lamport_call, &r.body.call_sha256) { rep.errors.push(format!("seq {s}: call not found in channel.jsonl at lamport {}", r.body.lamport_call)); }
                if !at(&results, r.body.lamport_result, &r.body.result_sha256) { rep.errors.push(format!("seq {s}: result not found in channel.jsonl at lamport {}", r.body.lamport_result)); }
            }
            "denied" => {
                if !denied.contains(&r.body.call_sha256) { rep.errors.push(format!("seq {s}: denied call not found in denied.jsonl")); }
            }
            "session" => {
                if !sessions.contains(&r.body.call_sha256) { rep.errors.push(format!("seq {s}: session policy not found in sessions.jsonl")); }
            }
            v => rep.errors.push(format!("seq {s}: unknown verdict {v}")),
        }
    })
}

/// Chain, signatures, key pin and anchors for any receipts.jsonl written by
/// `ReceiptLog`. `check` sees every parsed receipt and adds log-specific
/// errors (the gate cross-checks its channel; QHR and the router check their
/// verdict vocabulary).
pub fn verify_chain(dir: &Path, trust: &VerifyTrust, mut check: impl FnMut(&Receipt, &mut VerifyReport)) -> Result<VerifyReport, String> {
    let path = dir.join("receipts.jsonl");
    let f = File::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut rep = VerifyReport::default();

    // Resolve the public key: caller-supplied wins; the log dir is a fallback
    // that is only accepted when explicitly allowed.
    let mut pk: Option<(Scheme, Vec<u8>)> = None;
    if let Some(bytes) = &trust.pubkey {
        let scheme = Signer::scheme_for_pubkey_len(bytes.len()).ok_or("--pubkey: not an ML-DSA-65/87 public key")?;
        pk = Some((scheme, bytes.clone()));
    } else if let Some(found) = Signer::load_public(dir)? {
        if trust.fingerprint.is_none() && !trust.allow_unpinned {
            rep.errors.push("public key taken from the log dir and not pinned: pass --pubkey <file> or --fingerprint <hex> (or --allow-unpinned to check integrity only)".into());
        }
        pk = Some(found);
    }
    if let (Some((_, bytes)), Some(want)) = (&pk, &trust.fingerprint) {
        if sha256_hex(bytes) != want.to_lowercase() {
            rep.errors.push(format!("public key fingerprint {} does not match pinned {}", sha256_hex(bytes), want));
        }
    }
    let kid = pk.as_ref().map(|(_, b)| sha256_hex(b));
    rep.kid = kid.clone();

    let mut expect_seq = 0u64;
    let mut prev = GENESIS.to_string();
    let mut hashes: HashMap<u64, String> = HashMap::new();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        let r: Receipt = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => { rep.errors.push(format!("line {}: unparsable: {e}", i + 1)); continue; }
        };
        rep.receipts += 1;
        let s = r.body.seq;
        if r.body.v != RECEIPT_VERSION { rep.errors.push(format!("seq {s}: receipt version {} (expected {RECEIPT_VERSION})", r.body.v)); }
        if s != expect_seq { rep.errors.push(format!("seq {s}: expected seq {expect_seq}")); }
        if r.body.prev != prev { rep.errors.push(format!("seq {s}: prev hash mismatch")); }
        if r.body.hash() != r.hash { rep.errors.push(format!("seq {s}: body hash mismatch")); }
        if r.scheme != "none" {
            match (&pk, &r.sig) {
                (Some((scheme, pkb)), Some(sig)) if scheme.as_str() == r.scheme => {
                    if Some(&r.body.kid) != kid.as_ref() { rep.errors.push(format!("seq {s}: kid {} is not the trusted key", r.body.kid)); }
                    if !Signer::verify(*scheme, pkb, &signing_message(&r.hash), sig) {
                        rep.errors.push(format!("seq {s}: signature invalid"));
                    }
                }
                _ => rep.errors.push(format!("seq {s}: signed with {} but no matching public key / sig", r.scheme)),
            }
        } else if !r.body.kid.is_empty() {
            rep.errors.push(format!("seq {s}: unsigned receipt carries kid"));
        }
        check(&r, &mut rep);
        expect_seq = s + 1;
        hashes.insert(s, r.hash.clone());
        prev = r.hash;
    }
    if rep.receipts > 0 && pk.is_none() {
        rep.warnings.push("no public key: only unsigned receipts can be accepted".into());
    }
    if trust.allow_unpinned && trust.pubkey.is_none() && trust.fingerprint.is_none() {
        rep.warnings.push("unpinned key: integrity and order verified, authorship not".into());
    }

    // Anchors: the highest one that verifies against the trusted key must be
    // present in the file with the same hash. A valid anchor beyond the end
    // of the file is proof of truncation.
    let mut valid: Vec<(u64, String)> = trust.anchors.iter()
        .filter(|a| a.v == RECEIPT_VERSION && a.verify(pk.as_ref()))
        .map(|a| (a.seq, a.head.clone())).collect();
    let rejected = trust.anchors.len() - valid.len();
    if rejected > 0 { rep.warnings.push(format!("{rejected} anchor(s) ignored: not signed by the trusted key")); }
    if let Some((s, h)) = &trust.pinned_head { valid.push((*s, h.to_lowercase())); }
    if let Some((seq, head)) = valid.iter().max_by_key(|(s, _)| *s) {
        match hashes.get(seq) {
            Some(h) if h == head => rep.warnings.push(format!("anchor seq {seq} matches; receipts after it ({}) are not covered by an anchor", rep.receipts.saturating_sub(seq + 1))),
            Some(_) => rep.errors.push(format!("seq {seq}: hash differs from anchor (history rewritten)")),
            None => rep.errors.push(format!("TRUNCATED: anchor proves receipt seq {seq} existed (head {}), file ends at seq {}", head.get(..16).unwrap_or(head), expect_seq.saturating_sub(1))),
        }
    } else {
        rep.warnings.push("no anchor: tail truncation is not detectable; pass --anchor seq:hash or --anchor-file <peer channel.jsonl>".into());
    }
    Ok(rep)
}

// ---------------------------------------------------------------- signer

#[cfg(feature = "sign")]
type Secret = zeroize::Zeroizing<Vec<u8>>;

pub struct Signer {
    pub scheme: Scheme,
    /// SHA-256 hex of the public key; "" when unsigned.
    pub kid: String,
    pub public: Option<Vec<u8>>,
    /// True when the key was minted by this call (print the fingerprint).
    pub created: bool,
    #[cfg(feature = "sign")]
    secret: Option<Secret>,
}

impl Signer {
    fn pk_path(dir: &Path, scheme: Scheme) -> PathBuf { dir.join(format!("gate-{}.pk", scheme.as_str())) }
    #[cfg_attr(not(feature = "sign"), allow(dead_code))]
    fn sk_plain_path(dir: &Path, scheme: Scheme) -> PathBuf { dir.join(format!("gate-{}.sk", scheme.as_str())) }
    #[cfg_attr(not(feature = "sign"), allow(dead_code))]
    fn sk_dpapi_path(dir: &Path, scheme: Scheme) -> PathBuf { dir.join(format!("gate-{}.sk.dpapi", scheme.as_str())) }

    pub fn scheme_for_pubkey_len(len: usize) -> Option<Scheme> {
        match len { 1952 => Some(Scheme::MlDsa65), 2592 => Some(Scheme::MlDsa87), _ => None }
    }

    #[cfg_attr(not(feature = "sign"), allow(dead_code))]
    fn effective_store(cfg: &SignCfg) -> Result<KeyStore, String> {
        let store = match cfg.key_store {
            KeyStore::Auto => if cfg!(windows) { KeyStore::Dpapi } else { KeyStore::Plaintext },
            s => s,
        };
        if store == KeyStore::Plaintext && !cfg.insecure_plaintext_key {
            return Err("sign.key_store = plaintext requires sign.insecure_plaintext_key = true (or use dpapi on Windows)".into());
        }
        if store == KeyStore::Dpapi && !cfg!(windows) {
            return Err("sign.key_store = dpapi is Windows-only".into());
        }
        Ok(store)
    }

    pub fn load_or_create(dir: &Path, cfg: &SignCfg) -> Result<Self, String> {
        let scheme = cfg.scheme;
        #[cfg(not(feature = "sign"))]
        {
            let _ = dir;
            if scheme != Scheme::None {
                return Err(format!("sign.scheme = {} requires building with --features sign", scheme.as_str()));
            }
            Ok(Self { scheme, kid: String::new(), public: None, created: false })
        }
        #[cfg(feature = "sign")]
        {
            if scheme == Scheme::None { return Ok(Self { scheme, kid: String::new(), public: None, created: false, secret: None }); }
            let store = Self::effective_store(cfg)?;
            let pk_path = Self::pk_path(dir, scheme);
            let plain = Self::sk_plain_path(dir, scheme);
            let wrapped = Self::sk_dpapi_path(dir, scheme);

            let mut created = false;
            let secret: Secret = if let Ok(w) = fs::read(&wrapped) {
                Secret::new(keystore::unwrap(&w)?)
            } else if let Ok(p) = fs::read(&plain) {
                let s = Secret::new(p);
                if store == KeyStore::Dpapi {
                    // Migrate: wrap, then try to remove the plaintext copy.
                    fs::write(&wrapped, keystore::wrap(&s)?).map_err(|e| e.to_string())?;
                    if fs::remove_file(&plain).is_err() {
                        eprintln!("ductei-mcp-gate: WARNING plaintext key {} could not be removed after DPAPI migration; delete it by hand", plain.display());
                    }
                }
                s
            } else {
                let (pk, sk) = pq::keypair(scheme);
                let s = Secret::new(sk);
                fs::write(&pk_path, &pk).map_err(|e| e.to_string())?;
                match store {
                    KeyStore::Dpapi => fs::write(&wrapped, keystore::wrap(&s)?).map_err(|e| e.to_string())?,
                    _ => fs::write(&plain, &*s).map_err(|e| e.to_string())?,
                }
                created = true;
                s
            };
            let public = fs::read(&pk_path).map_err(|e| format!("read {}: {e}", pk_path.display()))?;
            if Self::scheme_for_pubkey_len(public.len()) != Some(scheme) {
                return Err(format!("{} is not a {} public key", pk_path.display(), scheme.as_str()));
            }
            let kid = sha256_hex(&public);
            if let Some(want) = &cfg.pubkey_fingerprint {
                if kid != want.to_lowercase() {
                    return Err(format!("signing key fingerprint {kid} does not match sign.pubkey_fingerprint {want}; refusing to start"));
                }
            }
            Ok(Self { scheme, kid, public: Some(public), created, secret: Some(secret) })
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Option<String> {
        #[cfg(feature = "sign")]
        {
            let sk = self.secret.as_ref()?;
            Some(to_hex(&pq::sign(self.scheme, sk, msg)))
        }
        #[cfg(not(feature = "sign"))]
        { let _ = msg; None }
    }

    /// Public key on disk, if any scheme has one. Untrusted unless pinned.
    pub fn load_public(dir: &Path) -> Result<Option<(Scheme, Vec<u8>)>, String> {
        for scheme in [Scheme::MlDsa87, Scheme::MlDsa65] {
            let p = Self::pk_path(dir, scheme);
            if let Ok(pk) = fs::read(&p) { return Ok(Some((scheme, pk))); }
        }
        Ok(None)
    }

    pub fn verify(scheme: Scheme, pk: &[u8], msg: &[u8], sig_hex: &str) -> bool {
        #[cfg(feature = "sign")]
        {
            match from_hex(sig_hex) {
                Some(sig) => pq::verify(scheme, pk, msg, &sig),
                None => false,
            }
        }
        #[cfg(not(feature = "sign"))]
        { let _ = (scheme, pk, msg, sig_hex); false }
    }
}

/// Secret key at rest. DPAPI user scope on Windows: only this Windows user
/// on this machine can unwrap it. Not a defence against that user, or against
/// anyone running as them; it is a defence against the file being copied.
#[cfg(all(feature = "sign", windows))]
mod keystore {
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN};
    use windows_sys::Win32::Foundation::LocalFree;

    fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
        unsafe { LocalFree(out.pbData as _); }
        v
    }

    pub fn wrap(secret: &[u8]) -> Result<Vec<u8>, String> {
        let input = CRYPT_INTEGER_BLOB { cbData: secret.len() as u32, pbData: secret.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        let desc: Vec<u16> = "ductei-mcp-gate signing key\0".encode_utf16().collect();
        let ok = unsafe { CryptProtectData(&input, desc.as_ptr(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out) };
        if ok == 0 { return Err("CryptProtectData failed".into()); }
        Ok(take(out))
    }

    pub fn unwrap(wrapped: &[u8]) -> Result<Vec<u8>, String> {
        let input = CRYPT_INTEGER_BLOB { cbData: wrapped.len() as u32, pbData: wrapped.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        let ok = unsafe { CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out) };
        if ok == 0 { return Err("CryptUnprotectData failed (key wrapped by another user or machine?)".into()); }
        Ok(take(out))
    }
}

#[cfg(all(feature = "sign", not(windows)))]
mod keystore {
    pub fn wrap(_: &[u8]) -> Result<Vec<u8>, String> { Err("DPAPI key store is Windows-only".into()) }
    pub fn unwrap(_: &[u8]) -> Result<Vec<u8>, String> { Err("DPAPI key store is Windows-only".into()) }
}

#[cfg(feature = "sign")]
mod pq {
    use super::Scheme;
    use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

    macro_rules! with_scheme {
        ($scheme:expr, $m:ident, $body:block) => {
            match $scheme {
                Scheme::MlDsa65 => { use pqcrypto_mldsa::mldsa65 as $m; $body }
                Scheme::MlDsa87 => { use pqcrypto_mldsa::mldsa87 as $m; $body }
                Scheme::None => unreachable!("no pq scheme"),
            }
        };
    }

    pub fn keypair(scheme: Scheme) -> (Vec<u8>, Vec<u8>) {
        with_scheme!(scheme, m, {
            let (pk, sk) = m::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        })
    }
    pub fn sign(scheme: Scheme, sk: &[u8], msg: &[u8]) -> Vec<u8> {
        with_scheme!(scheme, m, {
            let sk = m::SecretKey::from_bytes(sk).expect("stored secret key is well-formed");
            m::detached_sign(msg, &sk).as_bytes().to_vec()
        })
    }
    pub fn verify(scheme: Scheme, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        with_scheme!(scheme, m, {
            let (Ok(pk), Ok(sig)) = (m::PublicKey::from_bytes(pk), m::DetachedSignature::from_bytes(sig)) else { return false };
            m::verify_detached_signature(&sig, msg, &pk).is_ok()
        })
    }
}

// ---------------------------------------------------------------- gate state

/// What we remember between forwarding a call and seeing its result.
#[derive(Debug, Clone)]
pub struct PendingCall {
    pub key: String,
    pub scope: String,
    pub lamport_call: u64,
    pub call_sha256: String,
}

/// Client methods that pass without being listed in `policy.allow_methods`.
/// Everything else is denied: same deny-by-default rule as tools.
const BASE_CLIENT_METHODS: &[&str] = &["initialize", "ping", "tools/list", "tools/call"];

/// Everything the two relay threads share. Lives behind one Mutex.
pub struct Gate {
    pub server: String,
    pub node: [u8; 16],
    pub lamport: u64,
    pub channel: Channel,
    pub denied: LogStore,
    pub sessions: LogStore,
    pub receipts: ReceiptLog,
    pub pending: HashMap<String, PendingCall>,
    /// `tools/list` request ids awaiting a server answer to filter.
    pub pending_lists: HashSet<String>,
    pub allow: HashSet<String>,
    pub allow_methods: HashSet<String>,
    pub allow_server_methods: HashSet<String>,
    pub max_calls: u32,
    pub calls: u32,
    pub closed: bool,
    /// Anchor every N receipts (0 = off). Anchors also go to anchors.jsonl locally.
    pub anchor_every: u64,
    pub anchors: LogStore,
    /// Where anchor envelopes go to be pushed to peers (gate binary owns the thread).
    pub anchor_tx: Option<std::sync::mpsc::Sender<Envelope>>,
    /// Held for the gate's lifetime; the OS drops it if the process dies.
    _lock: File,
}

#[derive(Debug, PartialEq)]
pub enum Decision {
    /// Send this canonical line on to the other side.
    Forward(String),
    /// Do not forward; send this line back to whoever sent the original.
    Reply(String),
    /// Do not forward and do not answer (a denied notification, a junk line).
    Drop,
}

fn rpc_error(id: serde_json::Value, code: i64, message: &str) -> String {
    serde_json::json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}).to_string()
}

/// One gate per log dir: two gates appending to one receipts.jsonl would fork
/// the chain. The OS releases the lock when the process exits or dies, so
/// there is no stale-lock cleanup to get wrong.
fn lock_dir(dir: &Path) -> Result<File, String> {
    let f = OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("gate.lock")).map_err(|e| e.to_string())?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(fs::TryLockError::WouldBlock) => Err(format!("another ductei-mcp-gate is already using {}; one gate per log dir", dir.display())),
        Err(fs::TryLockError::Error(e)) => Err(format!("lock {}: {e}", dir.display())),
    }
}

impl Gate {
    pub fn open(cfg: &Config, dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let lock = lock_dir(dir)?;
        let mut policy = ScopePolicy::new();
        for t in &cfg.policy.allow { policy = policy.allow(&scope_for(&cfg.server.name, t)); }
        let channel = Channel::open(policy, dir.join("channel.jsonl"), dir.join("rejected.jsonl"))
            .map_err(|e| e.to_string())?;
        let node = load_or_create_node_id(dir).map_err(|e| e.to_string())?;
        let denied = LogStore::open(dir.join("denied.jsonl")).map_err(|e| e.to_string())?;
        let sessions = LogStore::open(dir.join("sessions.jsonl")).map_err(|e| e.to_string())?;
        let anchors = LogStore::open(dir.join("anchors.jsonl")).map_err(|e| e.to_string())?;
        // Resume the lamport clock past everything this node ever wrote, in every log.
        let mut max: Option<u64> = None;
        for envs in [channel.replay(0), denied.replay(0), sessions.replay(0), anchors.replay(0)] {
            for e in envs.map_err(|e| e.to_string())?.0.iter().filter(|e| e.node_id == node) {
                max = Some(max.map_or(e.lamport, |m| m.max(e.lamport)));
            }
        }
        Ok(Self {
            server: cfg.server.name.clone(),
            node,
            lamport: max.map_or(0, |l| l + 1),
            channel,
            denied,
            sessions,
            receipts: ReceiptLog::open_with(dir, &cfg.sign, Durability::from_log(&cfg.log))?,
            pending: HashMap::new(),
            pending_lists: HashSet::new(),
            allow: cfg.policy.allow.iter().cloned().collect(),
            allow_methods: cfg.policy.allow_methods.iter().cloned().collect(),
            allow_server_methods: cfg.policy.allow_server_methods.iter().cloned().collect(),
            max_calls: cfg.policy.max_calls_per_session,
            calls: 0,
            closed: false,
            anchor_every: cfg.anchor.every,
            anchors,
            anchor_tx: None,
            _lock: lock,
        })
    }

    fn next_lamport(&mut self) -> u64 { let l = self.lamport; self.lamport += 1; l }

    /// After a receipt: every N receipts, sign the chain head, append it to
    /// anchors.jsonl and hand it to the pusher. Local write first, so an
    /// anchor is never in flight without a record of it.
    fn maybe_anchor(&mut self) {
        if self.anchor_every == 0 || !self.receipts.seq.is_multiple_of(self.anchor_every) { return; }
        // An anchor asserts the head is on disk. Fast lane: make that true first.
        if let Err(e) = self.receipts.flush() { eprintln!("ductei-mcp-gate: receipts fsync before anchor failed: {e}; anchor skipped"); return; }
        let Some(env) = self.anchor_now() else { return };
        if let Err(e) = self.anchors.append(&env) { eprintln!("ductei-mcp-gate: anchors.jsonl append failed: {e}"); return; }
        if let Some(tx) = &self.anchor_tx { let _ = tx.send(env); }
    }

    /// Build an anchor envelope for the current head.
    pub fn anchor_now(&mut self) -> Option<Envelope> {
        let a = self.receipts.anchor()?;
        let blob = serde_json::to_vec(&a).unwrap_or_default();
        let key = format!("mcp/{}/anchor/{}", self.server, a.seq);
        let lamport = self.next_lamport();
        Some(scoped(&key, &[&anchor_scope(&self.server)], self.node, lamport, &blob))
    }

    /// Start-of-session receipt: the exact rules and server binary in force.
    /// Widening the allowlist or swapping the server exe shows up in the
    /// signed timeline as a new policy hash, not as a silent config edit.
    pub fn record_session(&mut self, policy: &str, launch: &str) -> Result<(), String> {
        let lamport = self.next_lamport();
        let key = format!("mcp/{}/session/{}", self.server, self.receipts.seq);
        let scope = format!("mcp:{}:session", self.server);
        let env = scoped(&key, &[&scope], self.node, lamport, policy.as_bytes());
        self.sessions.append(&env).map_err(|e| format!("sessions.jsonl: {e}"))?;
        self.receipts.record(ReceiptBody::new(key, scope, "session", lamport, lamport, sha256_hex(policy.as_bytes()), sha256_hex(launch.as_bytes())))
            .map_err(|e| format!("receipts.jsonl: {e}"))?;
        self.maybe_anchor();
        Ok(())
    }

    /// Mirrors ductei_core::SessionBudget (which is private and borrows the
    /// channel for its lifetime, so it can't be shared across relay threads).
    fn admit_call(&mut self) -> Result<(), ChannelError> {
        if self.closed { return Err(ChannelError::BoundReached); }
        if self.calls >= self.max_calls { self.closed = true; return Err(ChannelError::BoundReached); }
        self.calls += 1;
        Ok(())
    }

    /// A refusal goes on the timeline like anything else: denied.jsonl gets
    /// the envelope, receipts.jsonl gets a signed "denied" receipt.
    fn record_denied(&mut self, env: Envelope, call_sha256: String, reply: &str) {
        if let Err(e) = self.denied.append(&env) { eprintln!("ductei-mcp-gate: denied.jsonl append failed: {e}"); }
        let scope = env.scopes.first().map(|s| s.0.clone()).unwrap_or_default();
        let lamport_result = self.next_lamport();
        if let Err(e) = self.receipts.record(ReceiptBody::new(env.key.clone(), scope, "denied", env.lamport, lamport_result, call_sha256, sha256_hex(reply.as_bytes()))) {
            eprintln!("ductei-mcp-gate: denied receipt failed: {e}");
        }
        self.maybe_anchor();
    }

    /// Deny a non-tool method from either side (`kind` = "method" for the
    /// client, "server" for server-initiated requests).
    fn deny_method(&mut self, msg: &serde_json::Value, kind: &str, method: &str) -> Decision {
        let blob = serde_json::to_vec(msg).unwrap_or_default();
        let key = format!("mcp/{}/{kind}/{method}", self.server);
        let scope = format!("mcp:{}:{kind}:{method}", self.server);
        let lamport = self.next_lamport();
        let env = scoped(&key, &[&scope], self.node, lamport, &blob);
        let reply = msg.get("id").filter(|i| !i.is_null()).cloned()
            .map(|id| rpc_error(id, -32001, &format!("ductei: method {method} denied by policy")));
        self.record_denied(env, sha256_hex(&blob), reply.as_deref().unwrap_or(""));
        eprintln!("ductei-mcp-gate: denied {kind} {method}");
        reply.map_or(Decision::Drop, Decision::Reply)
    }

    /// A line from the client. Only JSON objects are relayed, and what is
    /// relayed is the gate's own re-serialization, never the raw bytes: a
    /// server whose parser reads duplicate keys or odd encodings differently
    /// must see exactly what the gate judged.
    pub fn on_client_line(&mut self, line: &str) -> Decision {
        let msg: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return Decision::Reply(rpc_error(serde_json::Value::Null, -32700, "ductei: parse error, line not relayed")),
        };
        // JSON-RPC batches were removed from MCP (2025-06-18); relaying an array would skip the gate.
        if !msg.is_object() {
            return Decision::Reply(rpc_error(serde_json::Value::Null, -32600, "ductei: batches and non-object messages are not relayed"));
        }
        let Some(method) = msg.get("method").and_then(|m| m.as_str()).map(String::from) else {
            // Our answer to a request the server was allowed to make.
            let is_response = msg.get("id").is_some() && (msg.get("result").is_some() || msg.get("error").is_some());
            return if is_response { Decision::Forward(msg.to_string()) }
                   else { Decision::Reply(rpc_error(serde_json::Value::Null, -32600, "ductei: invalid request")) };
        };
        if method.starts_with("notifications/") { return Decision::Forward(msg.to_string()); }
        match method.as_str() {
            "tools/call" => self.gate_call(msg),
            "tools/list" => {
                if let Some(id) = msg.get("id") { self.pending_lists.insert(id.to_string()); }
                Decision::Forward(msg.to_string())
            }
            m if BASE_CLIENT_METHODS.contains(&m) || self.allow_methods.contains(m) => Decision::Forward(msg.to_string()),
            m => { let m = m.to_string(); self.deny_method(&msg, "method", &m) }
        }
    }

    fn gate_call(&mut self, msg: serde_json::Value) -> Decision {
        // A call with no id would run on the server with no result to receipt.
        let Some(id) = msg.get("id").filter(|i| !i.is_null()).cloned() else {
            return Decision::Reply(rpc_error(serde_json::Value::Null, -32600, "ductei: tools/call needs an id"));
        };
        let id_str = id.to_string();
        // Reusing an in-flight id would pair the wrong result with the wrong receipt.
        if self.pending.contains_key(&id_str) {
            return Decision::Reply(rpc_error(id, -32600, "ductei: id already in flight"));
        }
        let tool = msg.pointer("/params/name").and_then(|t| t.as_str()).unwrap_or("").to_string();
        let scope = scope_for(&self.server, &tool);
        let key = format!("mcp/{}/{}/{}", self.server, tool, id_str.trim_matches('"'));
        let params = msg.get("params").cloned().unwrap_or(serde_json::Value::Null);
        let blob = serde_json::to_vec(&params).unwrap_or_default();
        let call_sha256 = sha256_hex(&blob);
        let lamport_call = self.next_lamport();
        let env = scoped(&key, &[&scope], self.node, lamport_call, &blob);

        match self.admit_call().and_then(|_| self.channel.send(env.clone())) {
            Ok(()) => {
                self.pending.insert(id_str, PendingCall { key, scope, lamport_call, call_sha256 });
                Decision::Forward(msg.to_string())
            }
            Err(e) => {
                let (code, text) = match &e {
                    ChannelError::ScopeDenied(_) => (-32001, format!("ductei: scope {scope} denied by policy")),
                    ChannelError::BoundReached => (-32002, "ductei: session bound reached".to_string()),
                    ChannelError::StaleDelta { .. } => (-32003, "ductei: stale delta rejected".to_string()),
                    ChannelError::Io(m) => (-32004, format!("ductei: persistence failed: {m}")),
                };
                let reply = rpc_error(id, code, &text);
                self.record_denied(env, call_sha256, &reply);
                Decision::Reply(reply)
            }
        }
    }

    /// A line from the server. Results of gated calls are persisted and
    /// receipted *before* the caller forwards them (persistence-before-ack).
    /// Server-initiated requests (sampling, elicitation, roots) are denied
    /// unless listed in `policy.allow_server_methods`.
    pub fn on_server_line(&mut self, line: &str) -> Result<Decision, ChannelError> {
        let Ok(mut msg) = serde_json::from_str::<serde_json::Value>(line) else {
            eprintln!("ductei-mcp-gate: dropped non-JSON line from server");
            return Ok(Decision::Drop);
        };
        if !msg.is_object() {
            eprintln!("ductei-mcp-gate: dropped non-object message from server");
            return Ok(Decision::Drop);
        }
        if let Some(method) = msg.get("method").and_then(|m| m.as_str()).map(String::from) {
            if method.starts_with("notifications/") || self.allow_server_methods.contains(&method) {
                return Ok(Decision::Forward(msg.to_string()));
            }
            return Ok(self.deny_method(&msg, "server", &method));
        }
        let Some(id) = msg.get("id").cloned() else { return Ok(Decision::Forward(msg.to_string())) };
        let id_str = id.to_string();

        if self.pending_lists.remove(&id_str) {
            let allow = &self.allow;
            if let Some(tools) = msg.pointer_mut("/result/tools").and_then(|t| t.as_array_mut()) {
                let before = tools.len();
                tools.retain(|t| t.get("name").and_then(|n| n.as_str()).is_some_and(|n| allow.contains(n)));
                if tools.len() != before { eprintln!("ductei-mcp-gate: tools/list filtered {} -> {}", before, tools.len()); }
            }
            return Ok(Decision::Forward(msg.to_string()));
        }

        let Some(p) = self.pending.remove(&id_str) else { return Ok(Decision::Forward(msg.to_string())) };
        let body = msg.get("result").or_else(|| msg.get("error")).cloned().unwrap_or(serde_json::Value::Null);
        let blob = serde_json::to_vec(&body).unwrap_or_default();
        let lamport_result = self.next_lamport();
        let mut env = scoped(&p.key, &[&p.scope], self.node, lamport_result, &blob);
        env.flags = 1; // response
        self.channel.send(env)?;
        self.receipts.record(ReceiptBody::new(p.key, p.scope, "accepted", p.lamport_call, lamport_result, p.call_sha256, sha256_hex(&blob)))
            .map_err(|e| ChannelError::Io(e.to_string()))?;
        self.maybe_anchor();
        Ok(Decision::Forward(msg.to_string()))
    }
}

/// Canonical JSON of the rules in force, recorded at the start of every
/// session. Lists are sorted so the same policy always hashes the same.
pub fn policy_json(cfg: &Config) -> String {
    let sorted = |v: &Vec<String>| { let mut v = v.clone(); v.sort(); v.dedup(); v };
    let exe = Path::new(&cfg.server.command);
    let server_sha256 = fs::read(exe).ok().map(|b| sha256_hex(&b));
    serde_json::json!({
        "v": 1,
        "server": cfg.server.name,
        "command": cfg.server.command,
        "args": cfg.server.args,
        "server_sha256": server_sha256,
        "allow": sorted(&cfg.policy.allow),
        "allow_methods": sorted(&cfg.policy.allow_methods),
        "allow_server_methods": sorted(&cfg.policy.allow_server_methods),
        "max_calls_per_session": cfg.policy.max_calls_per_session,
        "scheme": cfg.sign.scheme.as_str(),
        "pubkey_fingerprint": cfg.sign.pubkey_fingerprint,
        "anchor_peers": sorted(&cfg.anchor.peers),
    }).to_string()
}

/// Anchor peers must be on the tailnet (100.64.0.0/10, fd7a:115c:a1e0::/48)
/// or loopback unless explicitly allowed: the head hash and its timing are
/// nobody else's business.
pub fn peer_allowed(addr: &std::net::SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64),
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

// ---------------------------------------------------------------- launch nonce

/// Environment the gate gives the server it spawns. A server built to be
/// gate-only refuses to serve stdio unless `DUCTEI_GATE_NONCE` is present
/// and its SHA-256 equals the `nonce_sha256` in `gate-launch.json` next to
/// the logs (which the server can also check is owned by a live gate pid).
/// This stops accidental bypass (a client configured straight at the
/// server); it does not stop someone running as the same user on purpose.
pub const GATE_NONCE_ENV: &str = "DUCTEI_GATE_NONCE";
pub const GATE_LAUNCH_FILE: &str = "gate-launch.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct LaunchRecord {
    pub v: u32,
    pub gate_pid: u32,
    pub node_id: String,
    pub nonce_sha256: String,
    pub server: String,
}

/// Returns (nonce hex for the child's env, record written to the log dir).
pub fn new_launch(dir: &Path, server: &str, node: [u8; 16]) -> std::io::Result<(String, LaunchRecord)> {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|e| std::io::Error::other(e.to_string()))?;
    let nonce_hex = to_hex(&nonce);
    let rec = LaunchRecord { v: 1, gate_pid: std::process::id(), node_id: to_hex(&node), nonce_sha256: sha256_hex(nonce_hex.as_bytes()), server: server.into() };
    fs::write(dir.join(GATE_LAUNCH_FILE), serde_json::to_string(&rec)?)?;
    Ok((nonce_hex, rec))
}

/// Re-exported so the binary and tests share one Envelope type.
pub type Env = Envelope;

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(allow: &[&str], max: u32) -> Config {
        Config {
            server: ServerCfg { name: "t".into(), command: "true".into(), args: vec![] },
            policy: PolicyCfg { allow: allow.iter().map(|s| s.to_string()).collect(), max_calls_per_session: max, allow_methods: vec![], allow_server_methods: vec![] },
            log: LogCfg::default(),
            sign: SignCfg::default(),
            anchor: AnchorCfg::default(),
        }
    }

    /// A DUCTEI peer on localhost that accepts anchor envelopes for server "t",
    /// serving connections until the listener is dropped. Returns (addr, dir).
    fn anchor_peer() -> (String, PathBuf) {
        let d = tmp();
        let policy = ScopePolicy::new().allow(&anchor_scope("t"));
        let mut ch = Channel::open(policy, d.join("channel.jsonl"), d.join("rejected.jsonl")).unwrap();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(s) = s else { break };
                let _ = ductei_core::transport::serve_connection(s, &mut ch);
            }
        });
        (addr, d)
    }

    #[test]
    fn anchors_are_written_pushed_and_catch_truncation() {
        let (peer, peer_dir) = anchor_peer();
        let d = tmp();
        let mut c = cfg(&["echo"], 10);
        c.anchor = AnchorCfg { every: 1, peers: vec![peer.clone()], connect_timeout_ms: 2000, allow_public_peers: false, encrypt: false };
        let (tx, rx) = std::sync::mpsc::channel();
        let mut g = Gate::open(&c, &d).unwrap();
        g.anchor_tx = Some(tx);
        for id in 1..=3 {
            g.on_client_line(&call(id, "echo"));
            g.on_server_line(&format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{id}}}"#)).unwrap();
        }
        // Local anchors.jsonl has one per receipt, and the pusher gets the same envelopes.
        assert_eq!(g.anchors.replay(0).unwrap().0.len(), 3);
        let outbox = d.join("outbox.jsonl");
        let mut pushed = 0;
        while let Ok(env) = rx.try_recv() {
            assert_eq!(push_envelope(&peer, &env, std::time::Duration::from_secs(2), &outbox, false).unwrap(), 1);
            pushed += 1;
        }
        assert_eq!(pushed, 3);
        // The peer's log is the external anchor source.
        let anchors = anchors_in(&peer_dir.join("channel.jsonl")).unwrap();
        assert_eq!(anchors.len(), 3);
        assert_eq!(anchors.iter().map(|a| a.seq).max(), Some(2));
        let trust = VerifyTrust { allow_unpinned: true, anchors: anchors.clone(), ..Default::default() };
        let rep = verify_receipts(&d, &trust).unwrap();
        assert!(rep.ok(), "{:?}", rep.errors);
        // Drop the last receipt: chain still intact, anchor says it's missing.
        let p = d.join("receipts.jsonl");
        let keep: Vec<String> = fs::read_to_string(&p).unwrap().lines().take(2).map(String::from).collect();
        fs::write(&p, keep.join("\n") + "\n").unwrap();
        assert!(verify_receipts(&d, &unpinned()).unwrap().ok(), "chain alone cannot see truncation");
        let rep = verify_receipts(&d, &trust).unwrap();
        assert!(rep.errors.iter().any(|e| e.starts_with("TRUNCATED")), "{:?}", rep.errors);
    }

    #[test]
    fn deleting_a_repeated_channel_entry_is_caught() {
        // A polling client sends the same call and gets the same answer over
        // and over. Deleting one copy must still fail verification: receipts
        // are checked against the entry at their own Lamport stamp, not
        // against "this hash appears somewhere".
        let d = tmp();
        let mut g = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
        for id in 1..=3 {
            g.on_client_line(&call(id, "echo"));
            g.on_server_line(&format!(r#"{{"jsonrpc":"2.0","id":{id},"result":0}}"#)).unwrap();
        }
        drop(g);
        assert!(verify_receipts(&d, &unpinned()).unwrap().ok());
        let p = d.join("channel.jsonl");
        let lines: Vec<String> = fs::read_to_string(&p).unwrap().lines().map(String::from).collect();
        let mut kept = lines.clone();
        kept.remove(lines.len() / 2); // a middle call or result whose twin stays behind
        fs::write(&p, kept.join("\n") + "\n").unwrap();
        let rep = verify_receipts(&d, &unpinned()).unwrap();
        assert!(!rep.ok(), "deleted duplicate entry went unnoticed");
        assert!(rep.errors.iter().any(|e| e.contains("not found in channel.jsonl at lamport")), "{:?}", rep.errors);
    }

    #[test]
    fn unreachable_peer_does_not_block_or_lose_the_local_anchor() {
        let d = tmp();
        let mut c = cfg(&["echo"], 10);
        c.anchor = AnchorCfg { every: 1, peers: vec!["127.0.0.1:9".into()], connect_timeout_ms: 300, allow_public_peers: false, encrypt: false };
        let mut g = Gate::open(&c, &d).unwrap();
        g.on_client_line(&call(1, "echo"));
        g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":1}"#).unwrap();
        let env = g.anchor_now().unwrap();
        let t = std::time::Instant::now();
        assert!(push_envelope("127.0.0.1:9", &env, std::time::Duration::from_millis(300), &d.join("outbox.jsonl"), false).is_err());
        assert!(t.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(g.anchors.replay(0).unwrap().0.len(), 1);
    }

    #[test]
    fn launch_record_matches_nonce() {
        let d = tmp();
        let (nonce, rec) = new_launch(&d, "t", [7u8; 16]).unwrap();
        assert_eq!(sha256_hex(nonce.as_bytes()), rec.nonce_sha256);
        let on_disk: LaunchRecord = serde_json::from_str(&fs::read_to_string(d.join(GATE_LAUNCH_FILE)).unwrap()).unwrap();
        assert_eq!(on_disk.nonce_sha256, rec.nonce_sha256);
        assert_eq!(on_disk.gate_pid, std::process::id());
    }

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("ductei-mcp-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn unpinned() -> VerifyTrust { VerifyTrust { allow_unpinned: true, ..Default::default() } }

    fn call(id: u32, tool: &str) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{{"x":{id}}}}}}}"#)
    }

    #[test]
    fn allowed_tool_is_forwarded_then_receipted() {
        let d = tmp();
        let mut g = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
        assert!(matches!(g.on_client_line(&call(1, "echo")), Decision::Forward(_)));
        assert_eq!(g.pending.len(), 1);
        assert!(matches!(g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#).unwrap(), Decision::Forward(_)));
        assert!(g.pending.is_empty());
        let (log, _) = g.channel.replay(0).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].flags, 1);
        let rep = verify_receipts(&d, &unpinned()).unwrap();
        assert_eq!((rep.receipts, rep.errors.as_slice()), (1, &[][..]));
    }

    #[test]
    fn denied_tool_never_forwards_and_is_receipted() {
        let d = tmp();
        let mut g = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
        match g.on_client_line(&call(7, "rm_rf")) {
            Decision::Reply(r) => assert!(r.contains("-32001") && r.contains("\"id\":7")),
            d => panic!("denied call was not refused: {d:?}"),
        }
        assert!(g.pending.is_empty());
        assert_eq!(g.channel.replay(0).unwrap().0.len(), 0, "denied call must not enter channel log");
        assert_eq!(g.denied.replay(0).unwrap().0.len(), 1);
        let rep = verify_receipts(&d, &unpinned()).unwrap();
        assert_eq!(rep.receipts, 1);
        assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    }

    #[test]
    fn session_bound_closes_for_good() {
        let d = tmp();
        let mut g = Gate::open(&cfg(&["echo"], 1), &d).unwrap();
        assert!(matches!(g.on_client_line(&call(1, "echo")), Decision::Forward(_)));
        assert!(matches!(g.on_client_line(&call(2, "echo")), Decision::Reply(r) if r.contains("-32002")));
        assert!(matches!(g.on_client_line(&call(3, "echo")), Decision::Reply(r) if r.contains("-32002")));
    }

    #[test]
    fn non_call_methods_pass_through() {
        let d = tmp();
        let mut g = Gate::open(&cfg(&[], 10), &d).unwrap();
        assert!(matches!(g.on_client_line(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#), Decision::Forward(_)));
        assert!(matches!(g.on_client_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#), Decision::Forward(_)));
    }

    #[test]
    fn tools_list_is_filtered_to_allowlist() {
        let d = tmp();
        let mut g = Gate::open(&cfg(&["latest_frame", "events"], 10), &d).unwrap();
        assert!(matches!(g.on_client_line(r#"{"jsonrpc":"2.0","id":5,"method":"tools/list"}"#), Decision::Forward(_)));
        let answer = r#"{"jsonrpc":"2.0","id":5,"result":{"tools":[{"name":"latest_frame"},{"name":"delete_all"},{"name":"events"}],"nextCursor":null}}"#;
        let Decision::Forward(out) = g.on_server_line(answer).unwrap() else { panic!("list answer not forwarded") };
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let names: Vec<&str> = v["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["latest_frame", "events"]);
        assert!(v["result"].get("nextCursor").is_some(), "other result fields are kept");
        // A second answer with the same id is not a list answer any more: passed through whole.
        assert!(matches!(g.on_server_line(answer).unwrap(), Decision::Forward(s) if s.contains("delete_all")));
    }

    fn reply_code(d: Decision) -> i64 {
        let Decision::Reply(r) = d else { panic!("expected a reply, got {d:?}") };
        serde_json::from_str::<serde_json::Value>(&r).unwrap()["error"]["code"].as_i64().unwrap()
    }

    #[test]
    fn junk_batches_and_bad_ids_never_reach_the_server() {
        let d = tmp();
        let mut g = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
        assert_eq!(reply_code(g.on_client_line("not json")), -32700);
        // A batch would smuggle a denied call past the per-message gate.
        assert_eq!(reply_code(g.on_client_line(&format!("[{}]", call(1, "rm_rf")))), -32600);
        assert_eq!(reply_code(g.on_client_line(r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo"}}"#)), -32600);
        assert!(matches!(g.on_client_line(&call(4, "echo")), Decision::Forward(_)));
        assert_eq!(reply_code(g.on_client_line(&call(4, "echo"))), -32600, "in-flight id reused");
        assert_eq!(g.pending.len(), 1);
    }

    #[test]
    fn forwarded_line_is_what_the_gate_judged() {
        let d = tmp();
        let mut g = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
        // Duplicate "name": the gate's parser keeps one; the server must get that same one, once.
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rm_rf","name":"echo"}}"#;
        let judged = serde_json::from_str::<serde_json::Value>(line).unwrap()["params"]["name"].as_str().unwrap().to_string();
        match g.on_client_line(line) {
            Decision::Forward(out) => {
                assert_eq!(out.matches("\"name\"").count(), 1);
                assert!(out.contains(&format!("\"name\":\"{judged}\"")));
            }
            Decision::Reply(_) => assert_ne!(judged, "echo"),
            Decision::Drop => panic!("dropped"),
        }
    }

    #[test]
    fn non_tool_methods_are_deny_by_default_both_ways() {
        let d = tmp();
        let mut c = cfg(&["echo"], 10);
        c.policy.allow_methods = vec!["resources/list".into()];
        let mut g = Gate::open(&c, &d).unwrap();
        assert_eq!(reply_code(g.on_client_line(r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///etc"}}"#)), -32001);
        assert!(matches!(g.on_client_line(r#"{"jsonrpc":"2.0","id":2,"method":"resources/list"}"#), Decision::Forward(_)));
        assert_eq!(g.on_client_line(r#"{"jsonrpc":"2.0","method":"secret/notify"}"#), Decision::Drop);
        // Server asks the client's model to do something: refused, answered back to the server.
        assert_eq!(reply_code(g.on_server_line(r#"{"jsonrpc":"2.0","id":"s1","method":"sampling/createMessage","params":{}}"#).unwrap()), -32001);
        assert!(matches!(g.on_server_line(r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#).unwrap(), Decision::Forward(_)));
        // Every refusal is on the signed timeline.
        let rep = verify_receipts(&d, &unpinned()).unwrap();
        assert!(rep.ok(), "{:?}", rep.errors);
        assert_eq!(rep.receipts, 3);
    }

    #[test]
    fn second_gate_on_same_dir_is_refused() {
        let d = tmp();
        let _g = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
        assert!(Gate::open(&cfg(&["echo"], 10), &d).err().unwrap().contains("already using"));
    }

    #[test]
    fn damaged_chain_is_not_extended() {
        let d = tmp();
        {
            let mut g = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
            g.on_client_line(&call(1, "echo"));
            g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":1}"#).unwrap();
        }
        let p = d.join("receipts.jsonl");
        let mut text = fs::read_to_string(&p).unwrap();
        text.push_str("{\"torn\":"); // a crash mid-write
        fs::write(&p, text).unwrap();
        assert!(Gate::open(&cfg(&["echo"], 10), &d).err().unwrap().contains("refusing to extend"));
    }

    #[test]
    fn lamport_resumes_past_denied_and_anchor_writes() {
        let d = tmp();
        let mut c = cfg(&["echo"], 10);
        c.anchor.every = 1;
        let l1 = {
            let mut g = Gate::open(&c, &d).unwrap();
            g.on_client_line(&call(1, "nope")); // denied.jsonl + anchors.jsonl only
            g.lamport
        };
        assert!(Gate::open(&c, &d).unwrap().lamport >= l1);
    }

    #[test]
    fn session_receipt_records_policy_and_verifies() {
        let d = tmp();
        let mut c = cfg(&["echo"], 10);
        let mut g = Gate::open(&c, &d).unwrap();
        let p1 = policy_json(&c);
        g.record_session(&p1, "{}").unwrap();
        drop(g);
        c.policy.allow.push("delete_all".into());
        let p2 = policy_json(&c);
        assert_ne!(sha256_hex(p1.as_bytes()), sha256_hex(p2.as_bytes()), "widening the allowlist changes the recorded policy");
        Gate::open(&c, &d).unwrap().record_session(&p2, "{}").unwrap();
        let rep = verify_receipts(&d, &unpinned()).unwrap();
        assert!(rep.ok(), "{:?}", rep.errors);
        fs::write(d.join("sessions.jsonl"), "").unwrap();
        assert!(!verify_receipts(&d, &unpinned()).unwrap().ok(), "policy record removed");
    }

    #[test]
    fn anchor_peers_must_be_tailnet_or_loopback() {
        let ok = ["127.0.0.1:1", "100.64.0.1:1", "100.127.255.254:1", "[::1]:1", "[fd7a:115c:a1e0::1]:1"];
        let bad = ["100.128.0.1:1", "8.8.8.8:1", "192.168.1.5:1", "[2001:db8::1]:1"];
        for a in ok { assert!(peer_allowed(&a.parse().unwrap()), "{a}"); }
        for a in bad { assert!(!peer_allowed(&a.parse().unwrap()), "{a}"); }
        let env = scoped("k", &["s"], [0; 16], 0, b"x");
        assert!(push_envelope("8.8.8.8:1", &env, std::time::Duration::from_millis(100), &tmp().join("o.jsonl"), false).unwrap_err().contains("not a tailnet"));
    }

    #[test]
    fn tampered_receipt_fails_verify() {
        let d = tmp();
        let mut g = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
        g.on_client_line(&call(1, "echo"));
        g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":1}"#).unwrap();
        g.on_client_line(&call(2, "echo"));
        g.on_server_line(r#"{"jsonrpc":"2.0","id":2,"result":2}"#).unwrap();
        let p = d.join("receipts.jsonl");
        let text = fs::read_to_string(&p).unwrap().replace("\"verdict\":\"accepted\"", "\"verdict\":\"denied\"");
        fs::write(&p, text).unwrap();
        assert!(!verify_receipts(&d, &unpinned()).unwrap().ok());
    }

    fn body(i: u64) -> ReceiptBody {
        ReceiptBody::new("k".into(), "mcp:t:echo".into(), "accepted", i, i, sha256_hex(b"c"), sha256_hex(b"r"))
    }

    #[test]
    fn verified_tier_fsyncs_every_receipt() {
        let d = tmp();
        let mut log = ReceiptLog::open(&d, &SignCfg::default()).unwrap();
        for i in 0..5 { log.record(body(i)).unwrap(); assert_eq!(log.unsynced(), 0); }
        assert_eq!(log.syncs(), 5);
        assert_eq!(log.durability(), Durability::default());
    }

    #[test]
    fn fast_lane_fsyncs_by_count_and_on_flush() {
        let d = tmp();
        let dur = Durability { sync_every: 4, sync_max_ms: 0, background: false };
        let mut log = ReceiptLog::open_with(&d, &SignCfg::default(), dur).unwrap();
        for i in 0..10 { log.record(body(i)).unwrap(); }
        // 10 receipts, sync at 4 and 8, two left pending.
        assert_eq!(log.syncs(), 2);
        assert_eq!(log.unsynced(), 2);
        log.flush().unwrap();
        assert_eq!((log.syncs(), log.unsynced()), (3, 0));
        log.flush().unwrap();
        assert_eq!(log.syncs(), 3, "flush with nothing pending is a no-op");
        // Chain is intact and reopenable regardless of the sync schedule.
        drop(log);
        let reopened = ReceiptLog::open(&d, &SignCfg::default()).unwrap();
        assert_eq!(reopened.seq, 10);
    }

    #[test]
    fn fast_lane_fsyncs_by_time() {
        let d = tmp();
        let dur = Durability { sync_every: 1_000, sync_max_ms: 20, background: false };
        let mut log = ReceiptLog::open_with(&d, &SignCfg::default(), dur).unwrap();
        log.record(body(0)).unwrap();
        assert_eq!(log.syncs(), 0);
        std::thread::sleep(std::time::Duration::from_millis(40));
        log.record(body(1)).unwrap();
        assert_eq!((log.syncs(), log.unsynced()), (1, 0), "second record is past sync_max_ms");
    }

    #[test]
    fn fast_lane_gate_receipts_still_verify_and_anchor_flushes_first() {
        let d = tmp();
        let mut c = cfg(&["echo"], 10);
        c.log.sync_every = 100;
        c.anchor = AnchorCfg { every: 2, ..Default::default() };
        let mut g = Gate::open(&c, &d).unwrap();
        for i in 1..=3u32 {
            g.on_client_line(&call(i, "echo"));
            g.on_server_line(&format!(r#"{{"jsonrpc":"2.0","id":{i},"result":{i}}}"#)).unwrap();
        }
        // 3 call receipts (the session receipt is the binary's job). sync_every=100
        // would never have synced on its own; the anchor at seq 2 forced exactly
        // one fsync, and the third receipt is still pending.
        assert_eq!(g.receipts.seq, 3);
        assert_eq!(g.receipts.syncs(), 1, "anchor must fsync before asserting a head");
        assert_eq!(g.receipts.unsynced(), 1);
        g.receipts.flush().unwrap();
        assert_eq!((g.receipts.syncs(), g.receipts.unsynced()), (2, 0));
        assert!(verify_receipts(&d, &unpinned()).unwrap().ok());
    }

    #[test]
    fn background_flusher_drains_without_inline_fsync_and_backpressures() {
        let d = tmp();
        let dur = Durability { sync_every: 50, sync_max_ms: 5, background: true };
        let mut log = ReceiptLog::open_with(&d, &SignCfg::default(), dur).unwrap();
        for i in 0..10 { log.record(body(i)).unwrap(); }
        // Nothing was fsynced inline (10 < 50 and background mode ignores the timer inline).
        // Give the flusher a few intervals; it must drain on its own.
        let t = std::time::Instant::now();
        while log.unsynced() > 0 && t.elapsed() < std::time::Duration::from_secs(2) { std::thread::sleep(std::time::Duration::from_millis(2)); }
        assert_eq!(log.unsynced(), 0, "background thread did not drain");
        assert!(log.syncs() >= 1);
        // Backpressure: write faster than the flusher with a tiny window.
        let dur2 = Durability { sync_every: 3, sync_max_ms: 1_000, background: true };
        let d2 = tmp();
        let mut log2 = ReceiptLog::open_with(&d2, &SignCfg::default(), dur2).unwrap();
        for i in 0..9 { log2.record(body(i)).unwrap(); assert!(log2.unsynced() < 3, "backpressure must cap pending below sync_every"); }
        assert!(log2.syncs() >= 3);
    }

    #[test]
    fn dropping_a_background_log_leaves_nothing_pending_and_chain_reopens() {
        let d = tmp();
        {
            let dur = Durability { sync_every: 1_000, sync_max_ms: 10_000, background: true };
            let mut log = ReceiptLog::open_with(&d, &SignCfg::default(), dur).unwrap();
            for i in 0..7 { log.record(body(i)).unwrap(); }
            assert_eq!(log.unsynced(), 7);
            // drop: stops the thread, final flush
        }
        let reopened = ReceiptLog::open(&d, &SignCfg::default()).unwrap();
        assert_eq!(reopened.seq, 7);
    }

    #[test]
    fn log_cfg_background_mapping() {
        let c: LogCfg = toml::from_str("sync_every = 100\nsync_background = true").unwrap();
        assert_eq!(Durability::from_log(&c), Durability { sync_every: 100, sync_max_ms: DEFAULT_BACKGROUND_SYNC_MS, background: true });
        let c: LogCfg = toml::from_str("sync_background = true").unwrap();
        assert!(!Durability::from_log(&c).background, "verified tier never goes background");
        let c: LogCfg = toml::from_str("sync_every = 8\nsync_max_ms = 3\nsync_background = true").unwrap();
        assert_eq!(Durability::from_log(&c), Durability { sync_every: 8, sync_max_ms: 3, background: true });
    }

    #[test]
    fn log_cfg_durability_defaults_to_verified_tier() {
        let c: LogCfg = toml::from_str("").unwrap();
        assert_eq!((c.sync_every, c.sync_max_ms), (1, 0));
        let c: LogCfg = toml::from_str("sync_every = 0").unwrap();
        assert_eq!(Durability::from_log(&c).sync_every, 1, "0 is clamped, never 'never sync'");
        let c: LogCfg = toml::from_str("sync_every = 50\nsync_max_ms = 10").unwrap();
        assert_eq!(Durability::from_log(&c), Durability { sync_every: 50, sync_max_ms: 10, background: false });
    }

    #[test]
    fn receipt_without_matching_channel_entry_fails_verify() {
        let d = tmp();
        let mut g = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
        g.on_client_line(&call(1, "echo"));
        g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":1}"#).unwrap();
        assert!(verify_receipts(&d, &unpinned()).unwrap().ok());
        // Someone rewrites the channel log out from under the receipts.
        fs::write(d.join("channel.jsonl"), "").unwrap();
        let rep = verify_receipts(&d, &unpinned()).unwrap();
        assert!(rep.errors.iter().any(|e| e.contains("not found in channel.jsonl")), "{:?}", rep.errors);
    }

    #[test]
    fn lamport_resumes_across_restart() {
        let d = tmp();
        let l1 = {
            let mut g = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
            g.on_client_line(&call(1, "echo"));
            g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":1}"#).unwrap();
            g.lamport
        };
        let g2 = Gate::open(&cfg(&["echo"], 10), &d).unwrap();
        assert_eq!(g2.lamport, l1);
        assert_eq!(g2.receipts.seq, 1);
    }

    #[test]
    fn plaintext_key_store_needs_explicit_opt_in() {
        let c = SignCfg { scheme: Scheme::MlDsa65, key_store: KeyStore::Plaintext, pubkey_fingerprint: None, insecure_plaintext_key: false };
        assert!(Signer::effective_store(&c).is_err());
        let c = SignCfg { insecure_plaintext_key: true, ..c };
        assert_eq!(Signer::effective_store(&c).unwrap(), KeyStore::Plaintext);
    }

    #[cfg(feature = "sign")]
    mod signed {
        use super::*;

        fn signed_cfg(fp: Option<String>) -> Config {
            let mut c = cfg(&["echo"], 10);
            c.sign = SignCfg { scheme: Scheme::MlDsa65, key_store: KeyStore::Plaintext, pubkey_fingerprint: fp, insecure_plaintext_key: true };
            c
        }

        #[test]
        fn signed_receipts_verify_only_against_pinned_key() {
            let d = tmp();
            let kid = {
                let mut g = Gate::open(&signed_cfg(None), &d).unwrap();
                g.on_client_line(&call(1, "echo"));
                g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":1}"#).unwrap();
                g.on_client_line(&call(2, "nope"));
                g.receipts.signer.kid.clone()
            };
            // Unpinned, not allowed: error.
            assert!(!verify_receipts(&d, &VerifyTrust::default()).unwrap().ok());
            // Pinned by fingerprint: ok.
            let rep = verify_receipts(&d, &VerifyTrust { fingerprint: Some(kid.clone()), ..Default::default() }).unwrap();
            assert!(rep.ok(), "{:?}", rep.errors);
            assert_eq!(rep.receipts, 2);
            // Pinned by pubkey file: ok.
            let pk = fs::read(d.join("gate-ml-dsa-65.pk")).unwrap();
            assert!(verify_receipts(&d, &VerifyTrust { pubkey: Some(pk), ..Default::default() }).unwrap().ok());
            // Wrong fingerprint: fail.
            assert!(!verify_receipts(&d, &VerifyTrust { fingerprint: Some("00".repeat(32)), ..Default::default() }).unwrap().ok());
            // Attacker re-keys: delete the pair, run the gate again (new key), verify against the old pin fails.
            fs::remove_file(d.join("gate-ml-dsa-65.pk")).unwrap();
            fs::remove_file(d.join("gate-ml-dsa-65.sk")).unwrap();
            let mut g = Gate::open(&signed_cfg(None), &d).unwrap();
            g.on_client_line(&call(3, "echo"));
            g.on_server_line(r#"{"jsonrpc":"2.0","id":3,"result":3}"#).unwrap();
            let rep = verify_receipts(&d, &VerifyTrust { fingerprint: Some(kid), ..Default::default() }).unwrap();
            assert!(rep.errors.iter().any(|e| e.contains("not the trusted key") || e.contains("does not match pinned")), "{:?}", rep.errors);
        }

        #[test]
        fn gate_refuses_to_start_with_wrong_pinned_key() {
            let d = tmp();
            drop(Gate::open(&signed_cfg(None), &d).unwrap());
            assert!(Gate::open(&signed_cfg(Some("ff".repeat(32))), &d).is_err());
        }

        #[test]
        fn signature_is_domain_separated() {
            let d = tmp();
            let mut g = Gate::open(&signed_cfg(None), &d).unwrap();
            g.on_client_line(&call(1, "echo"));
            g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":1}"#).unwrap();
            let line = fs::read_to_string(d.join("receipts.jsonl")).unwrap();
            let r: Receipt = serde_json::from_str(line.lines().next().unwrap()).unwrap();
            let pk = g.receipts.signer.public.clone().unwrap();
            assert!(Signer::verify(Scheme::MlDsa65, &pk, &signing_message(&r.hash), r.sig.as_ref().unwrap()));
            assert!(!Signer::verify(Scheme::MlDsa65, &pk, r.hash.as_bytes(), r.sig.as_ref().unwrap()), "bare hash must not verify");
        }
    }

    #[cfg(not(feature = "qfltl"))]
    #[test]
    fn encrypt_without_the_feature_refuses_plaintext() {
        let a = AnchorCfg { every: 1, encrypt: true, ..AnchorCfg::default() };
        let d = tmp();
        let mut c = cfg(&["echo"], 10);
        c.anchor = a.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut g = Gate::open(&c, &d).unwrap();
        g.anchor_tx = Some(tx);
        g.on_client_line(&call(1, "echo"));
        g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":1}"#).unwrap();
        let env = rx.try_recv().unwrap();
        let err = push_anchor(&a, &d, "127.0.0.1:9", &env, &d.join("o.jsonl")).unwrap_err();
        assert!(err.contains("refusing plaintext"), "{err}");
    }

    #[cfg(feature = "qfltl")]
    mod qfltl_push {
        use super::*;
        use ductei_sync::qfltl_transport::{load_or_generate_identity, pin_key, serve_qfltl, PinRole};
        use ductei_sync::StateDir;
        use std::net::TcpListener;

        fn one_anchor() -> (Envelope, PathBuf) {
            let d = tmp();
            let mut c = cfg(&["echo"], 10);
            c.anchor = AnchorCfg { every: 1, peers: vec![], connect_timeout_ms: 2000, allow_public_peers: false, encrypt: true };
            let (tx, rx) = std::sync::mpsc::channel();
            let mut g = Gate::open(&c, &d).unwrap();
            g.anchor_tx = Some(tx);
            g.on_client_line(&call(1, "echo"));
            g.on_server_line(r#"{"jsonrpc":"2.0","id":1,"result":1}"#).unwrap();
            (rx.try_recv().unwrap(), d)
        }

        fn serve_one(root: &Path, gate_pub: &[u8]) -> (String, Vec<u8>, std::thread::JoinHandle<std::io::Result<()>>) {
            fs::create_dir_all(root).unwrap();
            let state = StateDir::open(root).unwrap();
            let kp = load_or_generate_identity(root).unwrap();
            pin_key(root, PinRole::Client, "gate", gate_pub, false).unwrap();
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap().to_string();
            let public = kp.public_bytes();
            let policy = ScopePolicy::new().allow(&anchor_scope("t"));
            let h = std::thread::spawn(move || {
                serve_qfltl(&state, l, policy, &["127.0.0.1".parse().unwrap()], Some(1), &kp, |_, _| {})
            });
            (addr, public, h)
        }

        #[test]
        fn encrypted_push_is_applied_by_a_pinned_peer() {
            let (env, d) = one_anchor();
            let gate_root = d.join("anchor-state");
            fs::create_dir_all(&gate_root).unwrap();
            let gate_kp = load_or_generate_identity(&gate_root).unwrap();
            let (addr, server_pub, h) = serve_one(&d.join("peer"), &gate_kp.public_bytes());
            pin_key(&gate_root, PinRole::Server, &addr, &server_pub, false).unwrap();
            let ack = push_envelope_qfltl(&gate_root, &addr, &env, std::time::Duration::from_secs(5), &d.join("outbox.jsonl"), false).unwrap();
            assert_eq!(ack, 1);
            h.join().unwrap().unwrap();
        }

        #[test]
        fn unpinned_peer_is_refused_before_anything_is_sent() {
            let (env, d) = one_anchor();
            let gate_root = d.join("anchor-state");
            fs::create_dir_all(&gate_root).unwrap();
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap().to_string();
            let outbox = d.join("outbox.jsonl");
            let err = push_envelope_qfltl(&gate_root, &addr, &env, std::time::Duration::from_secs(2), &outbox, false).unwrap_err();
            assert!(err.contains("no pinned server key"), "{err}");
            assert!(!outbox.exists(), "nothing may be recorded or sent");
        }

        #[test]
        fn wrong_pinned_key_fails_the_handshake_and_is_not_applied() {
            let (env, d) = one_anchor();
            let gate_root = d.join("anchor-state");
            fs::create_dir_all(&gate_root).unwrap();
            let gate_kp = load_or_generate_identity(&gate_root).unwrap();
            let (addr, _server_pub, h) = serve_one(&d.join("peer"), &gate_kp.public_bytes());
            let other_root = d.join("other");
            fs::create_dir_all(&other_root).unwrap();
            let impostor = load_or_generate_identity(&other_root).unwrap().public_bytes();
            pin_key(&gate_root, PinRole::Server, &addr, &impostor, false).unwrap();
            let err = push_envelope_qfltl(&gate_root, &addr, &env, std::time::Duration::from_secs(3), &d.join("outbox.jsonl"), false).unwrap_err();
            assert!(err.contains("handshake"), "{err}");
            let _ = h.join();
        }

        #[test]
        fn push_anchor_never_downgrades_to_plaintext() {
            let (env, d) = one_anchor();
            let a = AnchorCfg { every: 1, peers: vec![], connect_timeout_ms: 500, allow_public_peers: false, encrypt: true };
            let err = push_anchor(&a, &d.join("anchor-state"), "127.0.0.1:9", &env, &d.join("o.jsonl")).unwrap_err();
            assert!(!err.contains("connect:"), "must not have tried a plain connection: {err}");
        }
    }}
