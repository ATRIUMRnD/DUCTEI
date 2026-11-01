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
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub use ductei_mcp::{Durability, ReceiptBody, ReceiptLog, SignCfg, VerifyReport, VerifyTrust};

pub const HEARTBEAT_SCOPE: &str = "atrium.heartbeat";
pub const VERIFY_SCOPE: &str = "atrium.verify";

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
}
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
    /// Atomic replace: tmp file + rename, so a reader never sees a torn file.
    pub fn store(&self, state: &Path) -> std::io::Result<()> {
        let tmp = state.join("status.json.tmp");
        let dst = state.join("status.json");
        fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        let _ = fs::remove_file(&dst);
        fs::rename(&tmp, &dst)
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

struct Managed { child: Option<Child>, backoff: Duration, next_try: Instant, restarts: u64, started: Instant }

pub struct Supervisor {
    cfg: Config,
    log: ReceiptLog,
    managed: BTreeMap<String, Managed>,
    status: Status,
    tick: u64,
    last_beat: BTreeMap<String, u64>,
}

impl Supervisor {
    pub fn open(cfg: Config) -> Result<Self, String> {
        fs::create_dir_all(cfg.state.join("logs")).map_err(|e| format!("mkdir {}: {e}", cfg.state.display()))?;
        let log = ReceiptLog::open_in(&cfg.state, &cfg.state, &cfg.sign_cfg()?, Durability::default())?;
        let mut status = Status { supervisor_pid: std::process::id(), chain_seq: log.seq, chain_head: log.head.clone(), ..Default::default() };
        let now = now_unix();
        for r in &cfg.room {
            status.rooms.insert(r.name.clone(), RoomStatus { health: Health::Down, kind: r.kind.clone(), pid: None, restarts: 0, since_unix: now, note: String::new() });
        }
        let managed = cfg.room.iter().filter(|r| r.kind == Kind::Managed)
            .map(|r| (r.name.clone(), Managed { child: None, backoff: Duration::from_secs(1), next_try: Instant::now(), restarts: 0, started: Instant::now() })).collect();
        Ok(Self { cfg, log, managed, status, tick: 0, last_beat: BTreeMap::new() })
    }

    pub fn state(&self) -> &Path { &self.cfg.state }
    pub fn status(&self) -> &Status { &self.status }

    fn record(&mut self, key: &str, scope: &str, verdict: &str, call: &[u8], result: &[u8]) -> std::io::Result<()> {
        let body = ReceiptBody::new(key.to_string(), scope.to_string(), verdict, self.tick, self.tick, sha256_hex(call), sha256_hex(result));
        self.log.record(body)?;
        self.status.chain_seq = self.log.seq;
        self.status.chain_head = self.log.head.clone();
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
        let child = cmd.spawn().map_err(|e| format!("spawn {}: {e}", exe.display()))?;
        let pid = child.id();
        let m = self.managed.get_mut(&room.name).expect("managed entry");
        m.child = Some(child);
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
                        if let Ok(Some(st)) = c.try_wait() { exited = Some(st.code().unwrap_or(-1)); m.child = None; }
                    }
                    if let Some(code) = exited {
                        m.backoff = (m.backoff * 2).min(Duration::from_secs(30));
                        m.next_try = Instant::now() + m.backoff;
                        let note = format!("exit {code}, retry in {}s", m.backoff.as_secs());
                        self.status.rooms.get_mut(&r.name).unwrap().note = note;
                    }
                    let deps_up = r.requires.iter().all(|d| self.status.rooms.get(d).map(|s| s.health == Health::Up).unwrap_or(false));
                    let m = self.managed.get_mut(&r.name).expect("managed entry");
                    if m.child.is_none() && r.restart || m.child.is_none() && m.restarts == 0 {
                        if !deps_up { (Health::Blocked, None, format!("waiting for {}", r.requires.join(","))) }
                        else if Instant::now() < m.next_try { (Health::Down, None, self.status.rooms[&r.name].note.clone()) }
                        else {
                            match self.spawn(r) {
                                Ok(pid) => {
                                    let m = self.managed.get_mut(&r.name).unwrap();
                                    m.restarts += 1;
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

    /// Stop every managed child, record it, and leave status marking them down.
    pub fn shutdown(&mut self) -> std::io::Result<()> {
        let names: Vec<String> = self.managed.keys().cloned().collect();
        for n in names {
            if let Some(mut c) = self.managed.get_mut(&n).and_then(|m| m.child.take()) {
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
        let trust = VerifyTrust { pubkey: None, fingerprint: None, allow_unpinned: true, anchors: Vec::new(), pinned_head: None };
        let own = verify_own_chain(&self.cfg.state, &trust);
        let (ok, detail) = match own { Ok(rep) => (rep.ok(), format!("{} receipts, {} errors", rep.receipts, rep.errors.len())), Err(e) => (false, e) };
        if ok { pass += 1 } else { fail += 1 }
        report("atrium-chain", ok, &detail);
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
