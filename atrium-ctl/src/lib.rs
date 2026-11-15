// Copyright (C) 2026 xingxerx
// Licensed under the Apache License 2.0. See the LICENSE file in the repository root.

//! atrium-ctl: one supervisor for every ATRIUM room.
//!
//! A *room* is a long-running process the ecosystem depends on. Rooms are
//! either `external` (owned by a scheduled task or another supervisor; atrium
//! only watches them) or `managed` (atrium spawns, logs and restarts them).
//! Every tick the supervisor checks each room, and every state change (plus a
//! periodic beat) is recorded as a receipt on one hash-chained, optionally
//! ML-DSA-signed `receipts.jsonl`, reusing `ductei_mcp::ReceiptLog` so the
//! heartbeat chain verifies with the exact same code path as the gate and QHR.
//!
//! Invariants held here:
//! - persistence before status: a receipt is written before status.json moves.
//! - the supervisor never blocks a tick on a child; checks are bounded.
//! - a damaged chain is never extended (ReceiptLog refuses at open).
//! - a lost drive is never written through: the supervisor releases the chain,
//!   waits, reopens (which re-verifies), and records the gap (see `is_device_lost`).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub mod tree;
pub mod fleet;

pub use ductei_mcp::{Durability, ReceiptBody, ReceiptLog, SignCfg, VerifyReport, VerifyTrust};

pub const HEARTBEAT_SCOPE: &str = "atrium.heartbeat";
pub const VERIFY_SCOPE: &str = "atrium.verify";

/// One verify outcome: (name, passed, detail).
pub type Report = (String, bool, String);

/// First wait after a peer stops answering anchor pushes; doubles per miss.
pub const PEER_BACKOFF_MIN: Duration = Duration::from_secs(15);
/// Longest wait between anchor pushes to an unreachable peer.
pub const PEER_BACKOFF_MAX: Duration = Duration::from_secs(300);
/// Self-check: a full chain verify every N cheap tail checks (10 s each, so 10 min).
pub const FULL_CHECK_EVERY: u64 = 60;

// ---------------------------------------------------------------- config

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// State root: receipts.jsonl, status.json, pids.json, logs/.
    pub state: PathBuf,
    #[serde(default = "d_tick")]
    pub tick_ms: u64,
    /// Record a heartbeat receipt for every room at least every N ticks even
    /// without a state change (bounds "silence" in the chain).
    #[serde(default = "d_beat")]
    pub beat_every: u64,
    #[serde(default)]
    /// `[sign]` table in the gate's own format (scheme, key_store, pubkey_fingerprint).
    pub sign: Option<toml::Value>,
    #[serde(default)]
    pub room: Vec<Room>,
    #[serde(default)]
    pub verify: Vec<VerifyStep>,
    /// Chain-head anchoring, same `[anchor]` table and transport as the gate.
    /// Scope on the peer: `mcp:atrium:anchor`.
    #[serde(default)]
    pub anchor: ductei_mcp::AnchorCfg,
    /// Peer anchor exports (copied here by a verify step) that the own-chain
    /// check must agree with; catches a cut-off tail.
    #[serde(default)]
    pub anchor_files: Vec<PathBuf>,
    /// Phone control surface (`atrium fleet`).
    #[serde(default)]
    pub fleet: fleet::FleetCfg,
}

pub const ANCHOR_SERVER: &str = "atrium";
fn d_tick() -> u64 { 1000 }
fn d_beat() -> u64 { 60 }

/// How many ticks early room `idx` (of `n`) books its next beat, so the rooms'
/// beats land on different ticks instead of all on one. Each beat costs a
/// signed, fsynced receipt; seven on one tick froze the tick on a slow drive.
/// Always below `beat_every`, so silence in the chain stays bounded by it.
pub fn beat_offset(idx: usize, n: usize, beat_every: u64) -> u64 {
    if n <= 1 || beat_every <= 1 { return 0; }
    (idx as u64 % n as u64) * beat_every / n as u64
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Kind { #[default] External, Managed }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Room {
    pub name: String,
    #[serde(default)]
    pub kind: Kind,
    /// Image name to look for in the process table (external rooms, and a
    /// liveness cross-check for managed ones). Example: "ductei-node.exe".
    #[serde(default)]
    pub process: Option<String>,
    /// TCP endpoint that must accept a connection for the room to count as up.
    #[serde(default)]
    pub tcp: Option<String>,
    /// A file that must have been modified within `fresh_secs` (log or heartbeat file).
    #[serde(default)]
    pub fresh_file: Option<PathBuf>,
    #[serde(default = "d_fresh")]
    pub fresh_secs: u64,
    /// Managed rooms: what to run.
    #[serde(default)]
    pub exe: Option<PathBuf>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Managed rooms: restart on exit (with backoff 1s..30s).
    #[serde(default = "yes")]
    pub restart: bool,
    /// Rooms that must be up before this managed room is (re)started.
    #[serde(default)]
    pub requires: Vec<String>,
    /// External rooms: the Windows scheduled task that owns the room. When set,
    /// fleet `restart <room>` starts that task (schtasks /Run), nothing else.
    #[serde(default)]
    pub task: Option<String>,
}
fn d_fresh() -> u64 { 120 }
fn yes() -> bool { true }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifyStep {
    pub name: String,
    pub cmd: Vec<String>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub expect_exit: i32,
    /// If set, stdout+stderr must contain this text.
    #[serde(default)]
    pub expect_text: Option<String>,
    #[serde(default = "d_vto")]
    pub timeout_secs: u64,
    /// A step that may fail without failing verify (e.g. fetching from a peer
    /// that is off on purpose). The failure is still reported, as "skipped".
    #[serde(default)]
    pub optional: bool,
}
fn d_vto() -> u64 { 900 }

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }
    pub fn validate(&self) -> Result<(), String> {
        let mut seen = std::collections::BTreeSet::new();
        for r in &self.room {
            if !seen.insert(r.name.clone()) { return Err(format!("room {:?} listed twice", r.name)); }
            match r.kind {
                Kind::Managed if r.exe.is_none() => return Err(format!("managed room {:?} has no exe", r.name)),
                Kind::External if r.process.is_none() && r.tcp.is_none() && r.fresh_file.is_none() =>
                    return Err(format!("external room {:?} has no process, tcp or fresh_file check", r.name)),
                _ => {}
            }
            for req in &r.requires {
                if !self.room.iter().any(|x| &x.name == req) { return Err(format!("room {:?} requires unknown room {:?}", r.name, req)); }
            }
        }
        if self.tick_ms == 0 { return Err("tick_ms must be > 0".into()); }
        Ok(())
    }
    pub fn sign_cfg(&self) -> Result<SignCfg, String> {
        match &self.sign {
            Some(v) => v.clone().try_into().map_err(|e| format!("[sign]: {e}")),
            None => toml::from_str("").map_err(|e| format!("[sign] defaults: {e}")),
        }
    }
}

// ---------------------------------------------------------------- device loss

/// The drive under the state dir went away (USB drop, sleep, eject). Windows:
/// 21 ERROR_NOT_READY, 55 ERROR_DEV_NOT_EXIST, 433 ERROR_NO_SUCH_DEVICE,
/// 483 ERROR_DEVICE_HARDWARE_ERROR, 1006 ERROR_FILE_INVALID, 1117 ERROR_IO_DEVICE,
/// 1167 ERROR_DEVICE_NOT_CONNECTED. Only these trigger hold-and-resume; any other
/// I/O error still stops the supervisor (chain must not drift).
pub fn is_device_lost(e: &std::io::Error) -> bool {
    if let Some(code) = e.raw_os_error() {
        if cfg!(windows) && matches!(code, 21 | 55 | 433 | 483 | 1006 | 1117 | 1167) { return true; }
    }
    let m = e.to_string().to_ascii_lowercase();
    m.contains("device is not ready") || m.contains("device is not connected") || m.contains("no such device")
}

// ---------------------------------------------------------------- busy files

/// How long a write waits for a file another program holds open: 40 tries, 50 ms apart.
pub const BUSY_TRIES: u32 = 40;
pub const BUSY_WAIT: Duration = Duration::from_millis(50);

/// Another program (a backup copy, antivirus, the indexer) has the file open
/// without sharing it. Windows: 5 ERROR_ACCESS_DENIED (replacing a file a
/// reader holds), 32 ERROR_SHARING_VIOLATION, 33 ERROR_LOCK_VIOLATION. These
/// clear when the other program closes the file, so they are worth waiting for.
pub fn is_busy(e: &std::io::Error) -> bool {
    cfg!(windows) && matches!(e.raw_os_error(), Some(5 | 32 | 33))
}

/// Run one file operation, waiting out a busy file for up to
/// BUSY_TRIES * BUSY_WAIT (2 s). Any other error returns at once, and a file
/// that stays busy returns its last error, so the caller still stops loudly.
pub fn retry_busy<T>(mut op: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    let mut last = None;
    for _ in 0..BUSY_TRIES {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) if is_busy(&e) => { last = Some(e); std::thread::sleep(BUSY_WAIT); }
            Err(e) => return Err(e),
        }
    }
    Err(last.expect("BUSY_TRIES is at least 1"))
}

// ---------------------------------------------------------------- peer backoff

/// Per-peer anchor backoff. An unreachable peer (asleep laptop) is skipped
/// for anchors until its wait runs out, so a sleeping machine costs one log
/// line per backoff step instead of one timeout per receipt. Anchors are
/// cumulative (a later head covers earlier ones), so skipping loses nothing:
/// the peer gets the newest head once it answers again. Alarms ignore this.
#[derive(Debug, Default)]
pub struct PeerBackoff {
    down: BTreeMap<String, (Instant, Duration)>,
}

impl PeerBackoff {
    /// True when an anchor push to `peer` should be skipped right now.
    pub fn skip(&self, peer: &str, now: Instant) -> bool {
        self.down.get(peer).map(|(until, _)| now < *until).unwrap_or(false)
    }
    /// Peer answered. Returns true if it had been backed off (worth a log line).
    pub fn ok(&mut self, peer: &str) -> bool { self.down.remove(peer).is_some() }
    /// Peer missed. Returns the new wait.
    pub fn fail(&mut self, peer: &str, now: Instant) -> Duration {
        let wait = self.down.get(peer).map(|(_, w)| (*w * 2).min(PEER_BACKOFF_MAX)).unwrap_or(PEER_BACKOFF_MIN);
        self.down.insert(peer.to_string(), (now + wait, wait));
        wait
    }
}

/// Each peer lane keeps its own outbox, so two lanes never append to one file.
pub fn peer_outbox(state: &Path, peer: &str) -> PathBuf {
    let safe: String = peer.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    state.join(format!("anchor-outbox-{safe}.jsonl"))
}

/// One peer's anchor lane: its own queue, backoff and outbox, so a slow or
/// asleep peer (handshake timeouts) never delays anchors to the others.
/// Alarms always go out; of queued anchors only the newest (it covers the rest).
fn peer_lane(a: &ductei_mcp::AnchorCfg, state_root: &Path, logdir: &Path, peer: &str, rx: Receiver<Arc<ductei_core::Envelope>>) {
    let outbox = peer_outbox(logdir, peer);
    let mut backoff = PeerBackoff::default();
    while let Ok(first) = rx.recv() {
        let mut batch = vec![first];
        while let Ok(more) = rx.try_recv() { batch.push(more); }
        let (alarms, anchors): (Vec<_>, Vec<_>) = batch.into_iter().partition(|e| e.key.contains("/alarm/"));
        for env in alarms.iter().chain(anchors.last()) {
            let is_alarm = env.key.contains("/alarm/");
            if !is_alarm && backoff.skip(peer, Instant::now()) { continue; }
            match ductei_mcp::push_anchor(a, state_root, peer, env, &outbox) {
                Ok(1) | Ok(2) => {
                    if backoff.ok(peer) { slog(logdir, &format!("{peer} answering again; anchors resume at {}", env.key)); }
                }
                Ok(code) => slog(logdir, &format!("{} rejected by {peer} (ack {code})", env.key)),
                Err(e) => {
                    let wait = backoff.fail(peer, Instant::now());
                    slog(logdir, &format!("{} push to {peer} failed: {e}; next try in {}s", env.key, wait.as_secs()));
                }
            }
        }
    }
}

// ---------------------------------------------------------------- tail check

/// Where the verified part of receipts.jsonl ends, and the last verified line.
/// Lets the 10 s self-check read a few KB instead of the whole chain.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Tail {
    /// Byte offset just past the last verified line.
    pub end: u64,
    /// Seq the next line must carry.
    pub next_seq: u64,
    /// Hash the next line's `prev` must equal.
    pub head: String,
    /// Offset and bytes of the last verified line (re-read to catch a rewrite).
    pub last_off: u64,
    pub last_line: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum TailCheck {
    Ok,
    /// The file cannot be read right now (drive gone); not evidence of tampering.
    Unreadable(String),
    /// The file shrank, a verified line changed, or a new line breaks the chain.
    Bad(String),
}

const GENESIS_HEAD: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Build a Tail from the end of the file (reads at most the last 1 MiB).
/// Call only right after a full verify passed, so the last line is trusted.
pub fn tail_from_end(path: &Path) -> Result<Tail, String> {
    let mut f = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let len = f.metadata().map_err(|e| e.to_string())?.len();
    if len == 0 { return Ok(Tail { head: GENESIS_HEAD.into(), ..Default::default() }); }
    let window = len.min(1 << 20);
    let start = len - window;
    f.seek(SeekFrom::Start(start)).map_err(|e| e.to_string())?;
    let mut buf = Vec::with_capacity(window as usize);
    f.take(window).read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let last_nl = buf.iter().rposition(|&b| b == b'\n').ok_or("no complete line in the last 1 MiB")?;
    let line_start = match buf[..last_nl].iter().rposition(|&b| b == b'\n') {
        Some(p) => p + 1,
        None if start == 0 => 0,
        None => return Err("last line longer than 1 MiB".into()),
    };
    let line = &buf[line_start..last_nl];
    let r: ductei_mcp::Receipt = serde_json::from_slice(line).map_err(|e| format!("last line unparsable: {e}"))?;
    Ok(Tail { end: start + last_nl as u64 + 1, next_seq: r.body.seq + 1, head: r.hash, last_off: start + line_start as u64, last_line: line.to_vec() })
}

/// Cheap check: the file has not shrunk, the last verified line is unchanged,
/// and every new complete line links on (seq, prev, body hash). A line still
/// being written (no newline yet) is left for the next pass. Signatures are
/// left to the periodic full verify.
pub fn tail_check(path: &Path, t: &mut Tail) -> TailCheck {
    let mut f = match fs::File::open(path) { Ok(f) => f, Err(e) => return TailCheck::Unreadable(e.to_string()) };
    let len = match f.metadata() { Ok(m) => m.len(), Err(e) => return TailCheck::Unreadable(e.to_string()) };
    if len < t.end { return TailCheck::Bad(format!("receipts.jsonl shrank from {} to {len} bytes", t.end)); }
    if !t.last_line.is_empty() {
        let mut got = vec![0u8; t.last_line.len()];
        if let Err(e) = f.seek(SeekFrom::Start(t.last_off)).and_then(|_| f.read_exact(&mut got)) { return TailCheck::Unreadable(e.to_string()); }
        if got != t.last_line { return TailCheck::Bad(format!("verified receipt seq {} at byte {} was rewritten", t.next_seq.saturating_sub(1), t.last_off)); }
    }
    let mut buf = Vec::new();
    if let Err(e) = f.seek(SeekFrom::Start(t.end)).and_then(|_| f.read_to_end(&mut buf)) { return TailCheck::Unreadable(e.to_string()); }
    let mut pos = 0usize;
    while let Some(nl) = buf[pos..].iter().position(|&b| b == b'\n') {
        let line = &buf[pos..pos + nl];
        let r: ductei_mcp::Receipt = match serde_json::from_slice(line) {
            Ok(r) => r,
            Err(e) => return TailCheck::Bad(format!("byte {}: unparsable receipt: {e}", t.end)),
        };
        if r.body.seq != t.next_seq { return TailCheck::Bad(format!("seq {}: expected seq {}", r.body.seq, t.next_seq)); }
        if r.body.prev != t.head { return TailCheck::Bad(format!("seq {}: prev hash mismatch", r.body.seq)); }
        if r.body.hash() != r.hash { return TailCheck::Bad(format!("seq {}: body hash mismatch", r.body.seq)); }
        t.last_off = t.end;
        t.last_line = line.to_vec();
        t.end += nl as u64 + 1;
        t.next_seq += 1;
        t.head = r.hash;
        pos += nl + 1;
    }
    TailCheck::Ok
}

// ---------------------------------------------------------------- health

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Health { Up, Down, Blocked }

/// Image names currently in the process table (one bounded call per tick).
pub fn process_table() -> Vec<String> {
    #[cfg(windows)]
    { tree::processes().into_iter().map(|(_, name)| name).collect() }
    #[cfg(not(windows))]
    {
        let out = Command::new("ps").args(["-eo", "comm="]).stdout(Stdio::piped()).stderr(Stdio::null()).output();
        match out {
            Ok(o) => String::from_utf8_lossy(&o.stdout).lines().map(|l| l.trim().to_ascii_lowercase()).collect(),
            Err(_) => Vec::new(),
        }
    }
}

pub fn tcp_up(addr: &str, timeout: Duration) -> bool {
    addr.parse::<SocketAddr>().map(|a| TcpStream::connect_timeout(&a, timeout).is_ok()).unwrap_or(false)
}

pub fn fresh(path: &Path, max_age: Duration) -> bool {
    fs::metadata(path).and_then(|m| m.modified()).map(|t| t.elapsed().map(|e| e <= max_age).unwrap_or(true)).unwrap_or(false)
}

fn check_external(r: &Room, procs: &[String]) -> Health {
    let mut ok = true;
    if let Some(p) = &r.process { ok &= procs.iter().any(|x| x == &p.to_ascii_lowercase()); }
    if let Some(a) = &r.tcp { ok &= tcp_up(a, Duration::from_millis(200)); }
    if let Some(f) = &r.fresh_file { ok &= fresh(f, Duration::from_secs(r.fresh_secs)); }
    if ok { Health::Up } else { Health::Down }
}

// ---------------------------------------------------------------- status

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomStatus {
    pub health: Health,
    pub kind: Kind,
    pub pid: Option<u32>,
    pub restarts: u64,
    pub since_unix: u64,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Status {
    pub unix: u64,
    pub tick: u64,
    pub supervisor_pid: u32,
    pub chain_seq: u64,
    pub chain_head: String,
    pub rooms: BTreeMap<String, RoomStatus>,
    /// Set only when the supervisor stopped itself on a fatal error: why.
    /// `supervisor_pid == 0` with no reason is a clean `atrium down`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fatal: Option<String>,
}

impl Status {
    pub fn all_up(&self) -> bool { self.rooms.values().all(|r| r.health == Health::Up) }
    pub fn load(state: &Path) -> Result<Self, String> {
        let p = state.join("status.json");
        let t = fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?;
        serde_json::from_str(&t).map_err(|e| format!("parse {}: {e}", p.display()))
    }
    /// Atomic replace: tmp file + rename over the old file, so a reader always
    /// sees either the previous or the new status, never a torn or missing file.
    /// std's rename replaces an existing destination on Windows too (MoveFileEx
    /// with REPLACE_EXISTING), so no delete-first gap. A reader holding the old
    /// file open can make the replace fail for a moment; retry briefly.
    pub fn store(&self, state: &Path) -> std::io::Result<()> {
        let tmp = state.join("status.json.tmp");
        let dst = state.join("status.json");
        // A backup or scanner can hold either file for longer than a moment, so both
        // steps wait out a busy file (see `retry_busy`). The log names the file.
        let bytes = serde_json::to_vec_pretty(self)?;
        retry_busy(|| fs::write(&tmp, &bytes)).inspect_err(|e| slog(state, &format!("status.json.tmp could not be written: {e}")))?;
        retry_busy(|| fs::rename(&tmp, &dst)).inspect_err(|e| slog(state, &format!("status.json could not be replaced: {e}")))
    }
    /// True when another, still-running supervisor wrote this recently.
    /// `supervisor_pid == 0` means the last supervisor shut down cleanly.
    pub fn live(&self, max_age: Duration) -> bool {
        let age = now_unix().saturating_sub(self.unix);
        self.supervisor_pid != 0 && self.supervisor_pid != std::process::id()
            && age <= max_age.as_secs() && pid_alive(self.supervisor_pid)
    }
}

/// Is a process with this PID running (and is it an atrium binary)?
pub fn pid_alive(pid: u32) -> bool {
    #[cfg(windows)]
    { tree::processes().iter().any(|(p, name)| *p == pid && name.contains("atrium")) }
    #[cfg(not(windows))]
    { Path::new(&format!("/proc/{pid}")).exists() }
}

pub fn now_unix() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }

pub fn sha256_hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------- supervisor

struct Managed { child: Option<Child>, tree: Option<tree::Tree>, backoff: Duration, next_try: Instant, restarts: u64, spawned: bool, started: Instant }

/// Messages from a queued verify's worker threads to the tick thread.
enum JobMsg { Step(Report), StepsDone, Chain(Vec<Report>) }

/// A verify request being served by the live supervisor. Workers only run
/// commands and read files; every receipt is written on the tick thread.
struct VerifyJob { id: String, tx: Sender<JobMsg>, rx: Receiver<JobMsg>, lines: Vec<String>, pass: u32, fail: u32 }

pub struct Supervisor {
    cfg: Config,
    log: ReceiptLog,
    managed: BTreeMap<String, Managed>,
    status: Status,
    tick: u64,
    last_beat: BTreeMap<String, u64>,
    anchors: Option<ductei_core::LogStore>,
    anchor_tx: Option<std::sync::mpsc::Sender<ductei_core::Envelope>>,
    anchor_thread: Option<std::thread::JoinHandle<()>>,
    /// An `anchor.every` boundary was crossed since the last anchor. Anchors
    /// are cumulative, so one per tick (the newest head) covers every receipt
    /// written on that tick, instead of one fsynced anchor per receipt.
    anchor_pending: bool,
    node: [u8; 16],
    /// Receipts written so far, shared with the self-check thread.
    seq_shared: std::sync::Arc<std::sync::atomic::AtomicU64>,
    stop_check: std::sync::Arc<std::sync::atomic::AtomicBool>,
    check_thread: Option<std::thread::JoinHandle<()>>,
    /// The verify request currently being served (one at a time; others wait queued).
    job: Option<VerifyJob>,
    /// OS-level exclusive lock on `<state>/writer.lock`, held for this writer's
    /// whole life. The OS drops it when the process exits, even on a crash or kill.
    _writer_lock: fs::File,
}

impl Supervisor {
    pub fn open(cfg: Config) -> Result<Self, String> {
        fs::create_dir_all(cfg.state.join("logs")).map_err(|e| format!("mkdir {}: {e}", cfg.state.display()))?;
        // One writer per chain, enforced by the OS rather than by status.json:
        // a second `up`, or a standalone `verify`, cannot open the chain while
        // any other writer holds it, whether or not that writer published status.
        let lockp = cfg.state.join("writer.lock");
        let writer_lock = fs::OpenOptions::new().create(true).truncate(false).write(true).open(&lockp)
            .map_err(|e| format!("open {}: {e}", lockp.display()))?;
        writer_lock.try_lock().map_err(|_| format!("another atrium writer holds {} (one writer per chain); use `atrium check` to read, or queue `atrium verify` to the live supervisor", lockp.display()))?;
        let log = ReceiptLog::open_in(&cfg.state, &cfg.state, &cfg.sign_cfg()?, Durability::default())?;
        let mut status = Status { supervisor_pid: std::process::id(), chain_seq: log.seq, chain_head: log.head.clone(), ..Default::default() };
        let now = now_unix();
        for r in &cfg.room {
            status.rooms.insert(r.name.clone(), RoomStatus { health: Health::Down, kind: r.kind.clone(), pid: None, restarts: 0, since_unix: now, note: String::new() });
        }
        let managed = cfg.room.iter().filter(|r| r.kind == Kind::Managed)
            .map(|r| (r.name.clone(), Managed { child: None, tree: None, backoff: Duration::from_secs(1), next_try: Instant::now(), restarts: 0, spawned: false, started: Instant::now() })).collect();
        let mut node = [0u8; 16];
        node.copy_from_slice(&Sha256::digest(format!("atrium:{}", cfg.state.display()).as_bytes())[..16]);
        let mut sup = Self { cfg, log, managed, status, tick: 0, last_beat: BTreeMap::new(), anchors: None, anchor_tx: None, anchor_thread: None, anchor_pending: false, node,
            seq_shared: Default::default(), stop_check: Default::default(), check_thread: None, job: None, _writer_lock: writer_lock };
        sup.seq_shared.store(sup.log.seq, std::sync::atomic::Ordering::SeqCst);
        sup.start_anchoring()?;
        Ok(sup)
    }

    /// Local anchors.jsonl always; when peers are set, a dispatcher thread fans
    /// each envelope out to one lane per peer (`peer_lane`). Nothing here blocks
    /// a tick, and one slow peer never holds up another.
    fn start_anchoring(&mut self) -> Result<(), String> {
        let a = self.cfg.anchor.clone();
        if a.every == 0 { return Ok(()); }
        if a.encrypt && !cfg!(feature = "qfltl") {
            return Err("anchor.encrypt is set but this build has no `qfltl` feature; refusing plaintext anchors".into());
        }
        let store = ductei_core::LogStore::open(self.cfg.state.join("anchors.jsonl")).map_err(|e| format!("anchors.jsonl: {e}"))?;
        self.anchors = Some(store);
        if a.peers.is_empty() { return Ok(()); }
        let (tx, rx) = std::sync::mpsc::channel::<ductei_core::Envelope>();
        let state_root = self.cfg.state.join("anchor-state");
        let logdir = self.cfg.state.clone();
        self.anchor_tx = Some(tx);
        self.anchor_thread = Some(std::thread::spawn(move || {
            let mut lanes = Vec::new();
            for p in a.peers.clone() {
                let (ptx, prx) = channel::<Arc<ductei_core::Envelope>>();
                let (a, state_root, logdir) = (a.clone(), state_root.clone(), logdir.clone());
                let h = std::thread::spawn(move || peer_lane(&a, &state_root, &logdir, &p, prx));
                lanes.push((ptx, h));
            }
            while let Ok(env) = rx.recv() {
                let env = Arc::new(env);
                for (ptx, _) in &lanes { let _ = ptx.send(env.clone()); }
            }
            // Supervisor closed the queue: let every lane drain, then finish.
            for (ptx, h) in lanes { drop(ptx); let _ = h.join(); }
        }));
        Ok(())
    }

    /// Live self-check (only under `up`). Every 10 s a cheap tail check reads
    /// only what was appended since the last pass (plus the last verified line),
    /// and every `FULL_CHECK_EVERY` passes the whole chain is verified with
    /// signatures. A file that shrank, was rewritten, or holds fewer receipts
    /// than were written is reported to the anchor peers as
    /// `mcp/atrium/alarm/<seq>`. Two failures in a row are needed. An unreadable
    /// file (drive gone) is skipped, never reported as tampering.
    pub fn start_selfcheck(&mut self) {
        let Some(tx) = self.anchor_tx.clone() else { return };
        let (state, node, seqa, stop) = (self.cfg.state.clone(), self.node, self.seq_shared.clone(), self.stop_check.clone());
        self.check_thread = Some(std::thread::spawn(move || {
            use std::sync::atomic::Ordering::SeqCst;
            let path = state.join("receipts.jsonl");
            let (mut fails, mut reported) = (0u32, false);
            let mut tail: Option<Tail> = None;
            let mut pass: u64 = 0;
            'outer: loop {
                for _ in 0..10 { if stop.load(SeqCst) { break 'outer; } std::thread::sleep(Duration::from_secs(1)); }
                let exp = seqa.load(SeqCst);
                let full = tail.is_none() || pass.is_multiple_of(FULL_CHECK_EVERY);
                pass += 1;
                let problem = if full {
                    let trust = VerifyTrust { allow_unpinned: true, ..Default::default() };
                    match verify_own_chain(&state, &trust) {
                        Ok(r) if r.ok() && r.receipts >= exp => { tail = tail_from_end(&path).ok(); None }
                        Ok(r) => Some(format!("receipts.jsonl: {} on disk, {} written; {}", r.receipts, exp, r.errors.join(" | "))),
                        Err(_) if fs::metadata(&path).is_err() => continue, // drive gone: not tampering
                        Err(e) => Some(e),
                    }
                } else {
                    let t = tail.as_mut().expect("tail set after a full pass");
                    match tail_check(&path, t) {
                        TailCheck::Ok if t.next_seq >= exp => None,
                        TailCheck::Ok => Some(format!("receipts.jsonl: {} on disk, {} written", t.next_seq, exp)),
                        TailCheck::Unreadable(_) => continue,
                        TailCheck::Bad(p) => { tail = None; Some(p) } // next pass is a full verify
                    }
                };
                match problem {
                    None => { fails = 0; reported = false; }
                    Some(p) => {
                        fails += 1;
                        if fails >= 2 && !reported {
                            reported = true;
                            slog(&state, &format!("TAMPER: {p}"));
                            let env = ductei_core::scoped(&format!("mcp/{ANCHOR_SERVER}/alarm/{exp}"), &[&ductei_mcp::anchor_scope(ANCHOR_SERVER)], node, exp + 1, p.as_bytes());
                            if tx.send(env).is_err() { break; }
                        }
                    }
                }
            }
        }));
    }

    /// Sign the current head, write it locally, then hand it to the pusher.
    fn anchor_now(&mut self) {
        self.anchor_pending = false;
        let Some(store) = self.anchors.as_mut() else { return };
        let Some(a) = self.log.anchor() else { return };
        let blob = serde_json::to_vec(&a).unwrap_or_default();
        let key = format!("mcp/{ANCHOR_SERVER}/anchor/{}", a.seq);
        let env = ductei_core::scoped(&key, &[&ductei_mcp::anchor_scope(ANCHOR_SERVER)], self.node, a.seq + 1, &blob);
        if let Err(e) = store.append(&env) { slog(&self.cfg.state, &format!("anchors.jsonl append failed: {e}")); return; }
        if let Some(tx) = &self.anchor_tx { let _ = tx.send(env); }
    }

    /// One anchor for everything recorded since the last one, if a boundary was crossed.
    fn flush_anchor(&mut self) {
        if self.anchor_pending { self.anchor_now(); }
    }

    pub fn state(&self) -> &Path { &self.cfg.state }
    pub fn status(&self) -> &Status { &self.status }

    fn record(&mut self, key: &str, scope: &str, verdict: &str, call: &[u8], result: &[u8]) -> std::io::Result<()> {
        let body = ReceiptBody::new(key.to_string(), scope.to_string(), verdict, self.tick, self.tick, sha256_hex(call), sha256_hex(result));
        self.log.record(body)?;
        self.status.chain_seq = self.log.seq;
        self.status.chain_head = self.log.head.clone();
        self.seq_shared.store(self.log.seq, std::sync::atomic::Ordering::SeqCst);
        let every = self.cfg.anchor.every;
        if every > 0 && self.log.seq.is_multiple_of(every) { self.anchor_pending = true; }
        Ok(())
    }

    /// After a drive loss: one signed heartbeat receipt saying the chain paused
    /// at `from_seq` for `lost_secs` and why, so the gap is on the record.
    pub fn record_gap(&mut self, from_seq: u64, lost_secs: u64, why: &str) -> std::io::Result<()> {
        let call = format!("device-gap: chain paused at seq {from_seq} for {lost_secs}s");
        self.record("device-gap", HEARTBEAT_SCOPE, "gap", call.as_bytes(), why.as_bytes())?;
        self.anchor_now();
        Ok(())
    }

    /// Give up the chain without writing anything (the drive under it is gone).
    /// Stops the self-check, closes the anchor queue (lanes finish on their own),
    /// and drops the log, the writer lock and the managed children's job objects.
    pub fn release(mut self) {
        self.stop_check.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(t) = self.check_thread.take() { let _ = t.join(); }
        self.anchor_tx = None;
        let _ = self.anchor_thread.take(); // detached: a lane may be mid-timeout
        self.job = None;
    }

    fn spawn(&mut self, room: &Room) -> Result<u32, String> {
        let exe = room.exe.clone().ok_or("no exe")?;
        let logp = self.cfg.state.join("logs").join(format!("{}.log", room.name));
        let out = fs::OpenOptions::new().create(true).append(true).open(&logp).map_err(|e| format!("open {}: {e}", logp.display()))?;
        let err = out.try_clone().map_err(|e| e.to_string())?;
        let mut cmd = Command::new(&exe);
        cmd.args(&room.args).stdin(Stdio::null()).stdout(out).stderr(err).envs(&room.env);
        if let Some(c) = &room.cwd { cmd.current_dir(c); }
        let mut child = cmd.spawn().map_err(|e| format!("spawn {}: {e}", exe.display()))?;
        let pid = child.id();
        // Own the whole tree before the child starts grandchildren; fail closed.
        let tree = match tree::Tree::adopt(&child) {
            Ok(t) => t,
            Err(e) => { let _ = child.kill(); let _ = child.wait(); return Err(format!("{}: {e}", room.name)); }
        };
        let m = self.managed.get_mut(&room.name).expect("managed entry");
        m.child = Some(child);
        m.tree = Some(tree);
        m.started = Instant::now();
        Ok(pid)
    }

    /// One supervision tick. Returns the number of receipts written.
    pub fn tick(&mut self) -> std::io::Result<u64> {
        self.tick += 1;
        let procs = process_table();
        let rooms = self.cfg.room.clone();
        let n_rooms = rooms.len();
        let mut written = 0u64;
        for (idx, r) in rooms.iter().enumerate() {
            let (health, pid, note) = match r.kind {
                Kind::External => (check_external(r, &procs), None, String::new()),
                Kind::Managed => {
                    let m = self.managed.get_mut(&r.name).expect("managed entry");
                    // Reap.
                    let mut exited = None;
                    if let Some(c) = m.child.as_mut() {
                        if let Ok(Some(st)) = c.try_wait() { exited = Some(st.code().unwrap_or(-1)); m.child = None; m.tree = None; /* drop kills leftover grandchildren */ }
                    }
                    if let Some(code) = exited {
                        m.backoff = (m.backoff * 2).min(Duration::from_secs(30));
                        m.next_try = Instant::now() + m.backoff;
                        let note = format!("exit {code}, retry in {}s", m.backoff.as_secs());
                        self.status.rooms.get_mut(&r.name).unwrap().note = note;
                    }
                    let deps_up = r.requires.iter().all(|d| self.status.rooms.get(d).map(|s| s.health == Health::Up).unwrap_or(false));
                    let m = self.managed.get_mut(&r.name).expect("managed entry");
                    if m.child.is_none() && (r.restart || !m.spawned) {
                        if !deps_up { (Health::Blocked, None, format!("waiting for {}", r.requires.join(","))) }
                        else if Instant::now() < m.next_try { (Health::Down, None, self.status.rooms[&r.name].note.clone()) }
                        else {
                            match self.spawn(r) {
                                Ok(pid) => {
                                    let m = self.managed.get_mut(&r.name).unwrap();
                                    // The first spawn is a start, not a restart.
                                    if m.spawned { m.restarts += 1; } else { m.spawned = true; }
                                    (Health::Up, Some(pid), String::new())
                                }
                                Err(e) => {
                                    let m = self.managed.get_mut(&r.name).unwrap();
                                    m.backoff = (m.backoff * 2).min(Duration::from_secs(30));
                                    m.next_try = Instant::now() + m.backoff;
                                    (Health::Down, None, e)
                                }
                            }
                        }
                    } else if let Some(c) = m.child.as_ref() {
                        // Alive child; if it has been up a while, reset backoff.
                        if m.backoff > Duration::from_secs(1) && self.tick.is_multiple_of(60) { m.backoff = Duration::from_secs(1); }
                        let mut extra_ok = r.tcp.as_deref().map(|a| tcp_up(a, Duration::from_millis(200))).unwrap_or(true);
                        // A freshness file only counts against a child that has had fresh_secs to write it.
                        if let Some(f) = &r.fresh_file {
                            if m.started.elapsed() > Duration::from_secs(r.fresh_secs) { extra_ok &= fresh(f, Duration::from_secs(r.fresh_secs)); }
                        }
                        (if extra_ok { Health::Up } else { Health::Down }, Some(c.id()), String::new())
                    } else {
                        (Health::Down, None, self.status.rooms[&r.name].note.clone())
                    }
                }
            };
            let prev = self.status.rooms[&r.name].health;
            let restarts = self.managed.get(&r.name).map(|m| m.restarts).unwrap_or(0);
            let changed = prev != health || self.status.rooms[&r.name].pid != pid;
            let beat_due = self.tick.saturating_sub(*self.last_beat.get(&r.name).unwrap_or(&0)) >= self.cfg.beat_every;
            {
                let s = self.status.rooms.get_mut(&r.name).unwrap();
                if changed { s.since_unix = now_unix(); }
                s.health = health; s.pid = pid; s.restarts = restarts; s.note = note;
            }
            if changed || beat_due {
                let verdict = match health { Health::Up => "up", Health::Down => "down", Health::Blocked => "blocked" };
                let call = serde_json::to_vec(r)?;
                let result = serde_json::to_vec(&self.status.rooms[&r.name])?;
                self.record(&r.name, HEARTBEAT_SCOPE, verdict, &call, &result)?;
                // Booked a little early per room, so the next beats spread over
                // the minute instead of landing together on one tick.
                let early = beat_offset(idx, n_rooms, self.cfg.beat_every);
                self.last_beat.insert(r.name.clone(), self.tick.saturating_sub(early));
                written += 1;
            }
        }
        // One anchor for all of this tick's receipts (the newest head covers them).
        self.flush_anchor();
        self.status.tick = self.tick;
        self.status.unix = now_unix();
        // Persistence before status: receipts are already fsynced (Durability::default).
        self.status.store(&self.cfg.state)?;
        let pids: BTreeMap<&String, u32> = self.managed.iter().filter_map(|(n, m)| m.child.as_ref().map(|c| (n, c.id()))).collect();
        let pids_path = self.cfg.state.join("pids.json");
        let pids_bytes = serde_json::to_vec(&pids)?;
        retry_busy(|| fs::write(&pids_path, &pids_bytes)).inspect_err(|e| slog(&self.cfg.state, &format!("pids.json could not be written: {e}")))?;
        Ok(written)
    }

    /// Serve queued `atrium verify` requests without breaking one-writer-per-chain.
    /// A request is `<state>/requests/<id>.req`. Steps run on a worker thread
    /// (they only run commands); every receipt is written here, on the tick
    /// thread. After the last step receipt is on disk, the chain check runs
    /// read-only on another thread. The answer lands as `<id>.done`
    /// (tmp + rename). Never blocks a tick, so rooms stay up during verify.
    pub fn service_requests(&mut self) -> std::io::Result<()> {
        let dir = self.cfg.state.join("requests");
        if self.job.is_none() {
            let mut reqs: Vec<PathBuf> = match fs::read_dir(&dir) {
                Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.extension().map(|x| x == "req").unwrap_or(false)).collect(),
                Err(_) => return Ok(()),
            };
            reqs.sort();
            let Some(req) = reqs.into_iter().next() else { return Ok(()) };
            let id = req.file_stem().and_then(|s| s.to_str()).unwrap_or("verify").to_string();
            fs::rename(&req, dir.join(format!("{id}.running")))?;
            let (tx, rx) = channel();
            let (steps, wtx) = (self.cfg.verify.clone(), tx.clone());
            std::thread::spawn(move || {
                for s in &steps {
                    let (ok, d) = run_step(s);
                    if wtx.send(JobMsg::Step((s.name.clone(), ok, d))).is_err() { return; }
                }
                let _ = wtx.send(JobMsg::StepsDone);
            });
            slog(&self.cfg.state, &format!("verify request {id}: started, {} steps, rooms stay up", self.cfg.verify.len()));
            self.job = Some(VerifyJob { id, tx, rx, lines: Vec::new(), pass: 0, fail: 0 });
            return Ok(());
        }
        loop {
            let msg = match self.job.as_ref().map(|j| j.rx.try_recv()) { Some(Ok(m)) => m, _ => return Ok(()) };
            match msg {
                JobMsg::Step((name, ok, detail)) => {
                    let call = match self.cfg.verify.iter().find(|s| s.name == name) {
                        Some(s) => serde_json::to_vec(s)?,
                        None => name.clone().into_bytes(),
                    };
                    self.record(&name, VERIFY_SCOPE, if ok { "pass" } else { "fail" }, &call, detail.as_bytes())?;
                    self.flush_anchor();
                    slog(&self.cfg.state, &format!("verify {name}: {} {detail}", if ok { "PASS" } else { "FAIL" }));
                    let j = self.job.as_mut().expect("job");
                    if ok { j.pass += 1 } else { j.fail += 1 }
                    j.lines.push(format!("{} {name}: {detail}", if ok { "PASS" } else { "FAIL" }));
                }
                JobMsg::StepsDone => {
                    // Every step receipt is on disk now; the chain check only reads.
                    let (cfg, kid) = (self.cfg.clone(), self.log.anchor().map(|a| a.kid));
                    let tx = self.job.as_ref().expect("job").tx.clone();
                    std::thread::spawn(move || { let _ = tx.send(JobMsg::Chain(chain_reports(&cfg, kid.as_deref()))); });
                }
                JobMsg::Chain(reports) => {
                    let mut j = self.job.take().expect("job");
                    for (name, ok, detail) in reports {
                        slog(&self.cfg.state, &format!("verify {name}: {} {detail}", if ok { "PASS" } else { "FAIL" }));
                        if ok { j.pass += 1 } else { j.fail += 1 }
                        j.lines.push(format!("{} {name}: {detail}", if ok { "PASS" } else { "FAIL" }));
                    }
                    let code = if j.fail == 0 { 0 } else { 1 };
                    j.lines.push(format!("verify: {} pass, {} fail", j.pass, j.fail));
                    j.lines.push(format!("exit {code}"));
                    let tmp = dir.join(format!("{}.done.tmp", j.id));
                    fs::write(&tmp, j.lines.join("\n") + "\n")?;
                    fs::rename(&tmp, dir.join(format!("{}.done", j.id)))?;
                    let _ = fs::remove_file(dir.join(format!("{}.running", j.id)));
                    slog(&self.cfg.state, &format!("verify request {}: {} pass, {} fail", j.id, j.pass, j.fail));
                    return Ok(());
                }
            }
        }
    }

    /// Record a signed note that `file` was set aside from this chain. The
    /// receipt's result hash is the SHA-256 of the file's bytes, so anyone can
    /// later prove exactly what was quarantined. Anchors it, drains the pusher,
    /// and returns the file's SHA-256.
    pub fn record_repair(&mut self, file: &Path, why: &str) -> Result<String, String> {
        let bytes = fs::read(file).map_err(|e| format!("read {}: {e}", file.display()))?;
        let call = format!("chain-repair: quarantined {} ({why})", file.display());
        self.record("chain-repair", VERIFY_SCOPE, "pass", call.as_bytes(), &bytes).map_err(|e| format!("record: {e}"))?;
        self.anchor_now();
        self.anchor_tx = None;
        if let Some(t) = self.anchor_thread.take() { let _ = t.join(); }
        self.status.unix = now_unix();
        self.status.supervisor_pid = 0;
        self.status.store(&self.cfg.state).map_err(|e| e.to_string())?;
        Ok(sha256_hex(&bytes))
    }

    /// Stop every managed child, record it, and leave status marking them down.
    pub fn shutdown(&mut self) -> std::io::Result<()> { self.stop(None) }

    /// Same as `shutdown`, but status keeps the reason, so a crash never reads
    /// as a deliberate `atrium down` (the watchdog and the pager both act on it).
    pub fn shutdown_fatal(&mut self, why: &str) -> std::io::Result<()> { self.stop(Some(why)) }

    fn stop(&mut self, fatal: Option<&str>) -> std::io::Result<()> {
        // A verify still in flight is answered, so its caller never hangs.
        if let Some(j) = self.job.take() {
            let dir = self.cfg.state.join("requests");
            let _ = fs::write(dir.join(format!("{}.done", j.id)), format!("{}\nFAIL verify: interrupted by atrium down\nexit 1\n", j.lines.join("\n")));
            let _ = fs::remove_file(dir.join(format!("{}.running", j.id)));
        }
        let names: Vec<String> = self.managed.keys().cloned().collect();
        for n in names {
            let tree = self.managed.get_mut(&n).and_then(|m| m.tree.take());
            if let Some(mut c) = self.managed.get_mut(&n).and_then(|m| m.child.take()) {
                if let Some(t) = &tree { t.kill(); }
                tree::kill_tree_by_pid(c.id());
                let _ = c.kill();
                let _ = c.wait();
                if let Some(s) = self.status.rooms.get_mut(&n) { s.health = Health::Down; s.pid = None; s.note = if fatal.is_some() { "stopped: the supervisor hit a fatal error".into() } else { "stopped by atrium down".into() }; }
                let result = serde_json::to_vec(&self.status.rooms[&n])?;
                // On a fatal stop the chain may be the very thing that failed:
                // keep stopping rooms and still write the fatal mark below.
                let r = self.record(&n, HEARTBEAT_SCOPE, "stopped", n.as_bytes(), &result);
                if fatal.is_none() { r?; }
            }
        }
        self.status.unix = now_unix();
        self.status.supervisor_pid = 0;
        self.status.fatal = fatal.map(str::to_string);
        self.status.store(&self.cfg.state)?;
        let _ = fs::remove_file(self.cfg.state.join("pids.json"));
        // Self-check releases its sender first, or the pusher never drains.
        self.stop_check.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(t) = self.check_thread.take() { let _ = t.join(); }
        // Final head goes out even off an `every` boundary, then the pusher drains.
        self.anchor_now();
        self.anchor_tx = None;
        if let Some(t) = self.anchor_thread.take() { let _ = t.join(); }
        Ok(())
    }

    /// Run every verify step in order; each outcome is a receipt on the chain.
    /// Returns (passed, failed).
    pub fn run_verify(&mut self, mut report: impl FnMut(&str, bool, &str)) -> std::io::Result<(u32, u32)> {
        let steps = self.cfg.verify.clone();
        let (mut pass, mut fail) = (0u32, 0u32);
        for s in &steps {
            let (ok, detail) = run_step(s);
            if ok { pass += 1 } else { fail += 1 }
            let call = serde_json::to_vec(s)?;
            self.record(&s.name, VERIFY_SCOPE, if ok { "pass" } else { "fail" }, &call, detail.as_bytes())?;
            report(&s.name, ok, &detail);
        }
        // Finally the chain itself, after everything above is on it.
        let kid = self.log.anchor().map(|a| a.kid);
        for (name, ok, detail) in chain_reports(&self.cfg, kid.as_deref()) {
            if ok { pass += 1 } else { fail += 1 }
            report(&name, ok, &detail);
        }
        // verify is a one-shot process: anchor what it wrote and drain before exit.
        self.anchor_now();
        self.anchor_tx = None;
        if let Some(t) = self.anchor_thread.take() { let _ = t.join(); }
        self.status.unix = now_unix();
        self.status.store(&self.cfg.state)?;
        Ok((pass, fail))
    }
}

/// Verify the heartbeat chain: hash links, signatures (if pinned), and that
/// every receipt carries one of the scopes atrium writes.
pub fn verify_own_chain(state: &Path, trust: &VerifyTrust) -> Result<VerifyReport, String> {
    ductei_mcp::verify_chain(state, trust, |r, rep| {
        if r.body.scope != HEARTBEAT_SCOPE && r.body.scope != VERIFY_SCOPE {
            rep.errors.push(format!("seq {}: foreign scope {:?}", r.body.seq, r.body.scope));
        }
    })
}

/// The chain's signing key id, read from its first receipt (read-only; no lock).
pub fn own_kid(state: &Path) -> Option<String> {
    let f = fs::File::open(state.join("receipts.jsonl")).ok()?;
    let mut line = String::new();
    std::io::BufReader::new(f).read_line(&mut line).ok()?;
    serde_json::from_str::<serde_json::Value>(&line).ok()?.get("kid")?.as_str().map(str::to_string)
}

/// Read-only chain check: the heartbeat chain against the configured peer
/// anchors, plus the fleet chain. Only reads files, so any number of these can
/// run beside a live supervisor. A receipt caught mid-append can fail a pass,
/// so a failing result is re-checked once a second later before it counts.
pub fn chain_reports(cfg: &Config, own_kid: Option<&str>) -> Vec<Report> {
    let first = chain_reports_once(cfg, own_kid);
    if first.iter().all(|r| r.1) { return first; }
    std::thread::sleep(Duration::from_secs(1));
    chain_reports_once(cfg, own_kid)
}

fn chain_reports_once(cfg: &Config, own_kid: Option<&str>) -> Vec<Report> {
    let mut out = Vec::new();
    let mut anchors = Vec::new();
    let mut anchor_err = None;
    for f in &cfg.anchor_files {
        match ductei_mcp::anchors_in(f) {
            Ok(a) => anchors.extend(a),
            Err(e) => anchor_err = Some(e),
        }
    }
    // Anchors from other servers on the same peer log are not ours.
    anchors.retain(|a| Some(a.kid.as_str()) == own_kid);
    let n_anchors = anchors.len();
    let top = anchors.iter().map(|a| a.seq).max();
    let trust = VerifyTrust { pubkey: None, fingerprint: None, allow_unpinned: true, anchors, pinned_head: None, unsigned_through: None };
    let (ok, detail) = match verify_own_chain(&cfg.state, &trust) {
        Ok(rep) => {
            let ok = rep.ok() && anchor_err.is_none() && (cfg.anchor_files.is_empty() || n_anchors > 0);
            (ok, format!("{} receipts, {} errors{}; anchors {n_anchors} (top seq {}){}", rep.receipts, rep.errors.len(),
                if rep.errors.is_empty() { String::new() } else { format!(": {}", rep.errors.join(" | ")) },
                top.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                anchor_err.map(|e| format!("; anchor file: {e}")).unwrap_or_default()))
        }
        Err(e) => (false, e),
    };
    out.push(("atrium-chain".to_string(), ok, detail));
    // The phone's actions: separate chain, same pinned key, fleet scope only.
    let fdir = cfg.fleet.dir.clone().unwrap_or_else(|| cfg.state.join("fleet"));
    if fdir.join("receipts.jsonl").exists() {
        let pk = cfg.state.join("gate-ml-dsa-65.pk");
        let trust = VerifyTrust { pubkey: fs::read(&pk).ok(), allow_unpinned: false, ..Default::default() };
        let r = ductei_mcp::verify_chain(&fdir, &trust, |r, rep| {
            if r.body.scope != fleet::FLEET_SCOPE { rep.errors.push(format!("seq {}: foreign scope {:?}", r.body.seq, r.body.scope)); }
        });
        let (ok, detail) = match r { Ok(rep) => (rep.ok(), format!("{} receipts, {} errors{}", rep.receipts, rep.errors.len(), if rep.errors.is_empty() { String::new() } else { format!(": {}", rep.errors.join(" | ")) })), Err(e) => (false, e) };
        out.push(("fleet-chain".to_string(), ok, detail));
    }
    out
}

fn run_step(s: &VerifyStep) -> (bool, String) {
    let (ok, detail) = run_step_raw(s);
    optional_outcome(s.optional, ok, detail)
}

/// An optional step never fails verify; its failure is kept visible as "skipped".
fn optional_outcome(optional: bool, ok: bool, detail: String) -> (bool, String) {
    if ok || !optional { (ok, detail) } else { (true, format!("skipped (optional): {detail}")) }
}

fn run_step_raw(s: &VerifyStep) -> (bool, String) {
    if s.cmd.is_empty() { return (false, "empty cmd".into()); }
    let mut cmd = Command::new(&s.cmd[0]);
    cmd.args(&s.cmd[1..]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(c) = &s.cwd { cmd.current_dir(c); }
    let mut child = match cmd.spawn() { Ok(c) => c, Err(e) => return (false, format!("spawn {}: {e}", s.cmd[0])) };
    let deadline = Instant::now() + Duration::from_secs(s.timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= deadline => { let _ = child.kill(); let _ = child.wait(); return (false, format!("timeout after {}s", s.timeout_secs)); }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return (false, format!("wait: {e}")),
        }
    }
    let out = match child.wait_with_output() { Ok(o) => o, Err(e) => return (false, format!("output: {e}")) };
    let code = out.status.code().unwrap_or(-1);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    let mut ok = code == s.expect_exit;
    if let Some(t) = &s.expect_text { ok &= text.contains(t.as_str()); }
    let tail: String = text.lines().rev().take(3).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(" | ");
    (ok, format!("exit {code} (want {}){}", s.expect_exit, if tail.is_empty() { String::new() } else { format!(": {tail}") }))
}

/// Write a line to the supervisor log (state/logs/atrium.log) and stderr.
pub fn slog(state: &Path, msg: &str) {
    let line = format!("[{}] {msg}", now_unix());
    eprintln!("{line}");
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(state.join("logs").join("atrium.log")) {
        let _ = f.write_all(format!("{line}\n").as_bytes());
    }
}

#[cfg(test)]
mod busy_tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("target").join("test-sandbox").join(format!("busy-{name}-{}-{}", std::process::id(), now_unix()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn other_errors_return_at_once_and_success_passes_through() {
        let mut calls = 0;
        let r: std::io::Result<()> = retry_busy(|| { calls += 1; Err(std::io::Error::from_raw_os_error(112)) });
        assert!(r.is_err());
        assert_eq!(calls, 1, "disk full is not a busy file, no waiting");
        assert_eq!(retry_busy(|| Ok::<_, std::io::Error>(7)).unwrap(), 7);
    }

    #[cfg(windows)]
    #[test]
    fn a_file_that_stays_busy_fails_after_the_bounded_wait() {
        let mut calls = 0u32;
        let t = Instant::now();
        let r: std::io::Result<()> = retry_busy(|| { calls += 1; Err(std::io::Error::from_raw_os_error(32)) });
        assert_eq!(r.unwrap_err().raw_os_error(), Some(32));
        assert_eq!(calls, BUSY_TRIES);
        assert!(t.elapsed() >= BUSY_WAIT * (BUSY_TRIES - 1));
    }

    /// The backup case: a copy tool opens status.json and pids.json without sharing
    /// them while the supervisor ticks. The write must wait, not fail.
    #[cfg(windows)]
    #[test]
    fn status_store_and_plain_write_wait_out_an_exclusive_reader() {
        use std::os::windows::fs::OpenOptionsExt;
        let d = dir("reader");
        Status { tick: 1, ..Default::default() }.store(&d).unwrap();
        let pids = d.join("pids.json");
        fs::write(&pids, b"{}").unwrap();
        for name in ["status.json", "pids.json"] {
            let p = d.join(name);
            let (tx, rx) = channel();
            let holder = std::thread::spawn(move || {
                let f = fs::OpenOptions::new().read(true).share_mode(0).open(&p).unwrap();
                tx.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(400));
                drop(f);
            });
            rx.recv().unwrap();
            if name == "status.json" {
                Status { tick: 2, ..Default::default() }.store(&d).unwrap();
                assert_eq!(Status::load(&d).unwrap().tick, 2);
            } else {
                retry_busy(|| fs::write(&pids, b"{\"loop\":1}")).unwrap();
                assert_eq!(fs::read(&pids).unwrap(), b"{\"loop\":1}");
            }
            holder.join().unwrap();
        }
        let _ = fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod beat_tests {
    use super::*;

    #[test]
    fn beats_spread_over_the_minute_and_stay_bounded() {
        let n = 7;
        let offs: Vec<u64> = (0..n).map(|i| beat_offset(i, n, 60)).collect();
        assert_eq!(offs, vec![0, 8, 17, 25, 34, 42, 51]);
        // All rooms recorded together at tick 100: their next beats land on different ticks.
        let next: std::collections::BTreeSet<u64> = offs.iter().map(|o| 100 - o + 60).collect();
        assert_eq!(next.len(), n, "two rooms still beat on the same tick");
        // Silence in the chain never exceeds beat_every for any room.
        assert!(offs.iter().all(|o| *o < 60));
        assert_eq!(beat_offset(0, 1, 60), 0);
        assert_eq!(beat_offset(3, 7, 1), 0);
        assert_eq!(beat_offset(3, 7, 0), 0);
    }
}

#[cfg(test)]
mod backoff_tests {
    use super::*;

    #[test]
    fn backoff_doubles_caps_and_clears() {
        let mut b = PeerBackoff::default();
        let t0 = Instant::now();
        assert!(!b.skip("p", t0));
        assert_eq!(b.fail("p", t0), PEER_BACKOFF_MIN);
        assert!(b.skip("p", t0));
        assert!(!b.skip("p", t0 + PEER_BACKOFF_MIN));
        assert_eq!(b.fail("p", t0), PEER_BACKOFF_MIN * 2);
        for _ in 0..10 { b.fail("p", t0); }
        assert_eq!(b.fail("p", t0), PEER_BACKOFF_MAX);
        assert!(b.ok("p"));
        assert!(!b.ok("p"));
        assert!(!b.skip("p", t0));
    }

    #[test]
    fn peers_are_independent() {
        let mut b = PeerBackoff::default();
        let t0 = Instant::now();
        b.fail("laptop", t0);
        assert!(b.skip("laptop", t0));
        assert!(!b.skip("mini", t0));
    }

    #[test]
    fn each_peer_gets_its_own_outbox() {
        let s = Path::new("D:/x");
        let a = peer_outbox(s, "100.111.252.86:7421");
        let b = peer_outbox(s, "100.121.3.55:7421");
        assert_ne!(a, b);
        assert_eq!(a, Path::new("D:/x").join("anchor-outbox-100_111_252_86_7421.jsonl"));
    }

    #[test]
    fn a_dead_peer_lane_does_not_delay_a_live_one() {
        // One lane per peer: the lane for an unroutable peer (connect timeout)
        // must not hold back the queue of another lane. Model: two lanes fed
        // by one dispatcher; the slow lane sleeps, the fast lane must finish first.
        let (ftx, frx) = channel::<Arc<u32>>();
        let (stx, srx) = channel::<Arc<u32>>();
        let fast = std::thread::spawn(move || { let mut n = 0; while frx.recv().is_ok() { n += 1; } n });
        let slow = std::thread::spawn(move || { while srx.recv().is_ok() { std::thread::sleep(Duration::from_millis(200)); } });
        let t0 = Instant::now();
        for i in 0..5 { let e = Arc::new(i); let _ = ftx.send(e.clone()); let _ = stx.send(e); }
        drop(ftx);
        assert_eq!(fast.join().unwrap(), 5);
        assert!(t0.elapsed() < Duration::from_millis(200), "fast lane waited on the slow one");
        drop(stx);
        slow.join().unwrap();
    }
}

#[cfg(test)]
mod device_tests {
    use super::*;

    #[test]
    fn drive_loss_errors_are_recognised_and_others_are_not() {
        #[cfg(windows)]
        {
            assert!(is_device_lost(&std::io::Error::from_raw_os_error(21)));
            assert!(is_device_lost(&std::io::Error::from_raw_os_error(1167)));
            assert!(!is_device_lost(&std::io::Error::from_raw_os_error(5)), "access denied is not a lost drive");
            assert!(!is_device_lost(&std::io::Error::from_raw_os_error(112)), "disk full must still stop the supervisor");
        }
        assert!(is_device_lost(&std::io::Error::other("The device is not ready. (os error 21)")));
        assert!(!is_device_lost(&std::io::Error::other("chain broken")));
    }
}

#[cfg(test)]
mod tail_tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("atrium-tail-{name}-{}-{}", std::process::id(), now_unix()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn chain(d: &Path, n: u64) -> ReceiptLog {
        let mut log = ReceiptLog::open_in(d, d, &SignCfg::default(), Durability::default()).unwrap();
        for i in 0..n { log.record(ReceiptBody::new(format!("r{i}"), HEARTBEAT_SCOPE.into(), "up", i, i, sha256_hex(b"c"), sha256_hex(b"r"))).unwrap(); }
        log
    }

    #[test]
    fn appended_receipts_pass_and_advance() {
        let d = tmp("append");
        let mut log = chain(&d, 3);
        let p = d.join("receipts.jsonl");
        let mut t = tail_from_end(&p).unwrap();
        assert_eq!(t.next_seq, 3);
        for i in 3..6 { log.record(ReceiptBody::new(format!("r{i}"), HEARTBEAT_SCOPE.into(), "up", i, i, sha256_hex(b"c"), sha256_hex(b"r"))).unwrap(); }
        assert_eq!(tail_check(&p, &mut t), TailCheck::Ok);
        assert_eq!(t.next_seq, 6);
        assert_eq!(t.end, fs::metadata(&p).unwrap().len());
    }

    #[test]
    fn a_line_still_being_written_is_left_for_later() {
        let d = tmp("partial");
        drop(chain(&d, 2));
        let p = d.join("receipts.jsonl");
        let mut t = tail_from_end(&p).unwrap();
        fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(b"{\"v\":1,\"se").unwrap();
        assert_eq!(tail_check(&p, &mut t), TailCheck::Ok);
        assert_eq!(t.next_seq, 2);
    }

    #[test]
    fn truncation_and_rewrites_are_caught() {
        let d = tmp("bad");
        drop(chain(&d, 4));
        let p = d.join("receipts.jsonl");
        let text = fs::read_to_string(&p).unwrap();
        let mut t = tail_from_end(&p).unwrap();
        // Cut the last line off.
        let keep: Vec<&str> = text.lines().take(3).collect();
        fs::write(&p, keep.join("\n") + "\n").unwrap();
        assert!(matches!(tail_check(&p, &mut t), TailCheck::Bad(m) if m.contains("shrank")));
        // Same length, last verified line edited.
        fs::write(&p, &text).unwrap();
        let mut t = tail_from_end(&p).unwrap();
        fs::write(&p, text.replace("\"verdict\":\"up\"", "\"verdict\":\"dn\"")).unwrap();
        assert!(matches!(tail_check(&p, &mut t), TailCheck::Bad(m) if m.contains("rewritten")));
    }

    #[test]
    fn a_foreign_line_on_the_end_is_caught() {
        let d = tmp("foreign");
        drop(chain(&d, 2));
        let p = d.join("receipts.jsonl");
        let mut t = tail_from_end(&p).unwrap();
        let first = fs::read_to_string(&p).unwrap().lines().next().unwrap().to_string();
        fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(format!("{first}\n").as_bytes()).unwrap();
        assert!(matches!(tail_check(&p, &mut t), TailCheck::Bad(m) if m.contains("expected seq 2")));
    }

    #[test]
    fn missing_file_is_unreadable_not_tampering() {
        let d = tmp("gone");
        let mut t = Tail { end: 10, next_seq: 1, ..Default::default() };
        assert!(matches!(tail_check(&d.join("receipts.jsonl"), &mut t), TailCheck::Unreadable(_)));
    }
}

#[cfg(test)]
mod optional_step_tests {
    use super::*;

    #[test]
    fn optional_failure_is_skipped_not_failed() {
        let (ok, d) = optional_outcome(true, false, "exit 1".into());
        assert!(ok && d.starts_with("skipped (optional): exit 1"), "{d}");
    }

    #[test]
    fn required_failure_still_fails_and_success_is_untouched() {
        assert_eq!(optional_outcome(false, false, "exit 1".into()), (false, "exit 1".to_string()));
        assert_eq!(optional_outcome(true, true, "exit 0".into()), (true, "exit 0".to_string()));
    }

    #[test]
    fn optional_defaults_to_false_in_config() {
        let s: VerifyStep = toml::from_str("name = \"x\"\ncmd = [\"a\"]").unwrap();
        assert!(!s.optional);
        let s: VerifyStep = toml::from_str("name = \"x\"\ncmd = [\"a\"]\noptional = true").unwrap();
        assert!(s.optional);
    }
}
