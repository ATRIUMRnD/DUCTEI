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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, Write};
use std::sync::mpsc::{channel, Receiver, Sender};
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

// ---------------------------------------------------------------- health

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Health { Up, Down, Blocked }

/// Image names currently in the process table (one bounded call per tick).
pub fn process_table() -> Vec<String> {
    #[cfg(windows)]
    {
        let out = Command::new("tasklist").args(["/FO", "CSV", "/NH"]).stdout(Stdio::piped()).stderr(Stdio::null()).output();
        match out {
            Ok(o) => String::from_utf8_lossy(&o.stdout).lines()
                .filter_map(|l| l.trim_start_matches('"').split('"').next().map(|s| s.to_ascii_lowercase()))
                .collect(),
            Err(_) => Vec::new(),
        }
    }
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
        fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        let mut last = None;
        for _ in 0..5 {
            match fs::rename(&tmp, &dst) {
                Ok(()) => return Ok(()),
                Err(e) => { last = Some(e); std::thread::sleep(Duration::from_millis(20)); }
            }
        }
        Err(last.expect("rename attempted"))
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
    {
        let out = Command::new("tasklist").args(["/FO", "CSV", "/NH", "/FI", &format!("PID eq {pid}")])
            .stdout(Stdio::piped()).stderr(Stdio::null()).output();
        out.map(|o| String::from_utf8_lossy(&o.stdout).to_ascii_lowercase().contains("atrium")).unwrap_or(false)
    }
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
        let mut sup = Self { cfg, log, managed, status, tick: 0, last_beat: BTreeMap::new(), anchors: None, anchor_tx: None, anchor_thread: None, node,
            seq_shared: Default::default(), stop_check: Default::default(), check_thread: None, job: None, _writer_lock: writer_lock };
        sup.seq_shared.store(sup.log.seq, std::sync::atomic::Ordering::SeqCst);
        sup.start_anchoring()?;
        Ok(sup)
    }

    /// Local anchors.jsonl always; a pusher thread only when peers are set.
    /// The pusher never blocks a tick: newest anchor wins, older unsent ones
    /// are superseded (a later head covers them). A peer that stops answering
    /// is backed off for anchors (see `PeerBackoff`); alarms always try every peer.
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
        let outbox = self.cfg.state.join("anchor-outbox.jsonl");
        let logdir = self.cfg.state.clone();
        self.anchor_tx = Some(tx);
        self.anchor_thread = Some(std::thread::spawn(move || {
            let mut backoff = PeerBackoff::default();
            while let Ok(first) = rx.recv() {
                // Alarms always go out; of the anchors only the newest (it covers the rest).
                let mut batch = vec![first];
                while let Ok(more) = rx.try_recv() { batch.push(more); }
                let (alarms, anchors): (Vec<_>, Vec<_>) = batch.into_iter().partition(|e| e.key.contains("/alarm/"));
                for env in alarms.iter().chain(anchors.last()) {
                    let is_alarm = env.key.contains("/alarm/");
                    let mut ok = false;
                    let mut skipped = 0usize;
                    for p in &a.peers {
                        if !is_alarm && backoff.skip(p, Instant::now()) { skipped += 1; continue; }
                        match ductei_mcp::push_anchor(&a, &state_root, p, env, &outbox) {
                            Ok(1) | Ok(2) => {
                                ok = true;
                                if backoff.ok(p) { slog(&logdir, &format!("{p} answering again; anchors resume at {}", env.key)); }
                            }
                            Ok(code) => slog(&logdir, &format!("{} rejected by {p} (ack {code})", env.key)),
                            Err(e) => {
                                let wait = backoff.fail(p, Instant::now());
                                slog(&logdir, &format!("{} push to {p} failed: {e}; next try in {}s", env.key, wait.as_secs()));
                            }
                        }
                    }
                    // Only shout when no peer at all took it and none was merely backed off.
                    if !ok && skipped < a.peers.len() { slog(&logdir, &format!("{} unsent to any peer", env.key)); }
                }
            }
        }));
        Ok(())
    }

    /// Live self-check (only under `up`): every 10 s re-read receipts.jsonl
    /// from disk and compare it with what this process wrote. A file that no
    /// longer verifies, or holds fewer receipts than were written, is reported
    /// straight to the anchor peers as `mcp/atrium/alarm/<seq>`, where
    /// atrium-watch turns it into an alert. Two failures in a row are needed,
    /// so a line caught mid-write never alarms. Runs off the tick thread.
    pub fn start_selfcheck(&mut self) {
        let Some(tx) = self.anchor_tx.clone() else { return };
        let (state, node, seqa, stop) = (self.cfg.state.clone(), self.node, self.seq_shared.clone(), self.stop_check.clone());
        self.check_thread = Some(std::thread::spawn(move || {
            use std::sync::atomic::Ordering::SeqCst;
            let (mut fails, mut reported) = (0u32, false);
            'outer: loop {
                for _ in 0..10 { if stop.load(SeqCst) { break 'outer; } std::thread::sleep(Duration::from_secs(1)); }
                let exp = seqa.load(SeqCst);
                let trust = VerifyTrust { allow_unpinned: true, ..Default::default() };
                let problem = match verify_own_chain(&state, &trust) {
                    Ok(r) if r.ok() && r.receipts as u64 >= exp => None,
                    Ok(r) => Some(format!("receipts.jsonl: {} on disk, {} written; {}", r.receipts, exp, r.errors.join(" | "))),
                    Err(e) => Some(e),
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
        let Some(store) = self.anchors.as_mut() else { return };
        let Some(a) = self.log.anchor() else { return };
        let blob = serde_json::to_vec(&a).unwrap_or_default();
        let key = format!("mcp/{ANCHOR_SERVER}/anchor/{}", a.seq);
        let env = ductei_core::scoped(&key, &[&ductei_mcp::anchor_scope(ANCHOR_SERVER)], self.node, a.seq + 1, &blob);
        if let Err(e) = store.append(&env) { slog(&self.cfg.state, &format!("anchors.jsonl append failed: {e}")); return; }
        if let Some(tx) = &self.anchor_tx { let _ = tx.send(env); }
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
        if every > 0 && self.log.seq.is_multiple_of(every) { self.anchor_now(); }
        Ok(())
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
        let mut written = 0u64;
        for r in &rooms {
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
                self.last_beat.insert(r.name.clone(), self.tick);
                written += 1;
            }
        }
        self.status.tick = self.tick;
        self.status.unix = now_unix();
        // Persistence before status: receipts are already fsynced (Durability::default).
        self.status.store(&self.cfg.state)?;
        let pids: BTreeMap<&String, u32> = self.managed.iter().filter_map(|(n, m)| m.child.as_ref().map(|c| (n, c.id()))).collect();
        fs::write(self.cfg.state.join("pids.json"), serde_json::to_vec(&pids)?)?;
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
    pub fn shutdown(&mut self) -> std::io::Result<()> {
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
                if let Some(s) = self.status.rooms.get_mut(&n) { s.health = Health::Down; s.pid = None; s.note = "stopped by atrium down".into(); }
                let result = serde_json::to_vec(&self.status.rooms[&n])?;
                self.record(&n, HEARTBEAT_SCOPE, "stopped", n.as_bytes(), &result)?;
            }
        }
        self.status.unix = now_unix();
        self.status.supervisor_pid = 0;
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
    let trust = VerifyTrust { pubkey: None, fingerprint: None, allow_unpinned: true, anchors, pinned_head: None };
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
        let _ = writeln!(f, "{line}");
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
}
