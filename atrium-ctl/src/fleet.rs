// Copyright (C) 2026 xingxerx
// Licensed under the Apache License 2.0. See the LICENSE file in the repository root.

//! `atrium fleet`: one allowlisted control surface for xing-pc, the laptop and
//! the Mac mini. Claude (xing-pc-mcp presets) and the Telegram bot both call
//! this, never a shell. Every action is a signed receipt on its own chain
//! (`<fleet.dir>/receipts.jsonl`), so the phone's commands are on the record.
//!
//! Remote machines are reached with a dedicated SSH key whose authorized_keys
//! entry is pinned to a forced-command wrapper: even a stolen fleet key can
//! only ask for `status`, `alarms` or `restart-anchor`.

use crate::{now_unix, sha256_hex, Config, Durability, Health, ReceiptBody, ReceiptLog, Status};
use serde::Deserialize;
use std::fs;
use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const FLEET_SCOPE: &str = "atrium.fleet";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FleetCfg {
    /// Chain + lock + bot state. Defaults to `<state>/fleet`.
    #[serde(default)]
    pub dir: Option<PathBuf>,
    #[serde(default)]
    pub machine: Vec<Machine>,
    /// Telegram bot: env file with TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.
    #[serde(default)]
    pub telegram_env: Option<PathBuf>,
    /// xing-pc-mcp's audit chain. When set, the bot pushes every new
    /// unauthorized hit on the public /mcp endpoint to the chat.
    #[serde(default)]
    pub mcp_audit: Option<PathBuf>,
    /// ductei-agent's outbox (one JSON or text line per report). The bot
    /// forwards every new line, so the agent never holds the bot token.
    #[serde(default)]
    pub agent_outbox: Option<PathBuf>,
    /// HTTPS URL of the ATRIUM Mini App (matrix rain + command board). When
    /// set, the chat's menu button opens it; otherwise the menu button opens
    /// the / command list. Static page only: it holds no token and no secrets.
    #[serde(default)]
    pub miniapp_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Machine {
    pub name: String,
    /// Tailscale address.
    pub host: String,
    /// user@host for the forced-command fleet key. None = local machine.
    #[serde(default)]
    pub ssh: Option<String>,
    #[serde(default)]
    pub key: Option<PathBuf>,
    /// Wake-on-LAN: MAC and LAN broadcast address.
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default = "d_bcast")]
    pub broadcast: String,
}
fn d_bcast() -> String { "255.255.255.255".into() }

/// The whole verb list. Anything else is refused before it runs.
pub const USAGE: &str = "atrium fleet <config> status
atrium fleet <config> alarms
atrium fleet <config> wake <machine>
atrium fleet <config> up
atrium fleet <config> down --yes
atrium fleet <config> restart <room> --yes
atrium fleet <config> restart-anchor <machine> --yes
atrium fleet <config> bot";

fn run(cmd: &[String], timeout: Duration) -> (i32, String) {
    let mut c = Command::new(&cmd[0]);
    c.args(&cmd[1..]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match c.spawn() { Ok(c) => c, Err(e) => return (-1, format!("spawn {}: {e}", cmd[0])) };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= deadline => { let _ = child.kill(); let _ = child.wait(); return (-1, format!("timeout after {}s", timeout.as_secs())); }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return (-1, e.to_string()),
        }
    }
    let mut out = String::new();
    if let Some(mut o) = child.stdout.take() { let _ = o.read_to_string(&mut out); }
    if let Some(mut e) = child.stderr.take() { let _ = e.read_to_string(&mut out); }
    let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
    (code, out.trim().to_string())
}

fn reachable(host: &str) -> bool {
    format!("{host}:22").to_socket_addrs().ok().and_then(|mut a| a.next())
        .map(|a| TcpStream::connect_timeout(&a, Duration::from_millis(1500)).is_ok()).unwrap_or(false)
}

fn remote(m: &Machine, verb: &str) -> (i32, String) {
    let (Some(ssh), Some(key)) = (&m.ssh, &m.key) else { return (-1, "no fleet ssh configured".into()) };
    let cmd: Vec<String> = ["ssh", "-i", &key.to_string_lossy(), "-o", "BatchMode=yes", "-o", "ConnectTimeout=4", "-o", "StrictHostKeyChecking=yes", ssh, verb]
        .iter().map(|s| s.to_string()).collect();
    run(&cmd, Duration::from_secs(10))
}

fn wol(mac: &str, bcast: &str) -> Result<(), String> {
    let b: Vec<u8> = mac.split([':', '-']).map(|h| u8::from_str_radix(h, 16)).collect::<Result<_, _>>().map_err(|e| format!("mac {mac}: {e}"))?;
    if b.len() != 6 { return Err(format!("mac {mac}: want 6 bytes")); }
    let mut pkt = vec![0xFFu8; 6];
    for _ in 0..16 { pkt.extend(&b); }
    let s = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    s.set_broadcast(true).map_err(|e| e.to_string())?;
    for port in [9, 7] { s.send_to(&pkt, (bcast, port)).map_err(|e| e.to_string())?; }
    Ok(())
}

pub struct Fleet { cfg: Config, fc: FleetCfg, dir: PathBuf }

impl Fleet {
    pub fn new(cfg: Config) -> Self {
        let fc = cfg.fleet.clone();
        let dir = fc.dir.clone().unwrap_or_else(|| cfg.state.join("fleet"));
        Self { cfg, fc, dir }
    }

    fn machine(&self, name: &str) -> Result<&Machine, String> {
        self.fc.machine.iter().find(|m| m.name == name).ok_or_else(|| format!("unknown machine {name:?} (known: {})", self.fc.machine.iter().map(|m| m.name.as_str()).collect::<Vec<_>>().join(", ")))
    }

    /// Append one signed receipt for an action. A lock file keeps concurrent
    /// callers (bot + Claude) from interleaving writes on the chain.
    fn record(&self, action: &str, ok: bool, detail: &str) {
        let _ = fs::create_dir_all(&self.dir);
        let lock = self.dir.join("receipts.lock");
        let t0 = Instant::now();
        let held = loop {
            match fs::OpenOptions::new().write(true).create_new(true).open(&lock) {
                Ok(_) => break true,
                Err(_) if t0.elapsed() < Duration::from_secs(5) => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => {
                    // A crashed holder leaves a stale lock; older than 30 s is reclaimed.
                    let stale = fs::metadata(&lock).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).map(|e| e > Duration::from_secs(30)).unwrap_or(false);
                    if stale { let _ = fs::remove_file(&lock); continue; }
                    break false;
                }
            }
        };
        if !held { eprintln!("fleet: chain busy, action not recorded: {action}"); return; }
        let res = (|| -> Result<(), String> {
            let sign = self.cfg.sign_cfg()?;
            // Same pinned atrium key (it lives in the state dir), separate chain file.
            let mut log = ReceiptLog::open_in(&self.dir, &self.cfg.state, &sign, Durability::default())?;
            let n = log.seq;
            log.record(ReceiptBody::new(format!("fleet/{n}"), FLEET_SCOPE.into(), if ok { "ok" } else { "fail" }, n, n, sha256_hex(action.as_bytes()), sha256_hex(detail.as_bytes())))
                .map(|_| ()).map_err(|e| e.to_string())
        })();
        let _ = fs::remove_file(&lock);
        if let Err(e) = res { eprintln!("fleet: receipt failed: {e}"); }
        let line = format!("{} {} {} {}\n", now_unix(), if ok { "ok" } else { "FAIL" }, action, detail.lines().next().unwrap_or(""));
        let _ = fs::OpenOptions::new().create(true).append(true).open(self.dir.join("actions.log")).and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
    }

    /// Run one verb. Returns (ok, human text). Every call is recorded.
    pub fn exec(&self, args: &[String]) -> (bool, String) {
        let yes = args.iter().any(|a| a == "--yes");
        let a: Vec<&str> = args.iter().filter(|a| *a != "--yes").map(|s| s.as_str()).collect();
        let (ok, text) = match a.as_slice() {
            ["status"] => (true, self.status()),
            ["alarms"] => match self.fc.machine.iter().find(|m| m.ssh.is_some() && m.name == "mini") {
                Some(m) => { let (c, t) = remote(m, "alarms"); (c == 0, if t.is_empty() { "no alarms".into() } else { t }) }
                None => (false, "no mini configured".into()),
            },
            ["wake", name] => match self.machine(name) {
                Ok(m) => match &m.mac {
                    Some(mac) => match wol(mac, &m.broadcast) { Ok(()) => (true, format!("magic packet sent to {} ({mac}); check status in ~20 s", m.name)), Err(e) => (false, e) },
                    None => (false, format!("{}: no MAC configured for wake", m.name)),
                },
                Err(e) => (false, e),
            },
            ["up"] => { let (c, t) = run(&["schtasks".into(), "/Run".into(), "/TN".into(), "atrium".into()], Duration::from_secs(15)); (c == 0, if c == 0 { "atrium task started".into() } else { t }) }
            ["down"] if yes => { let (c, t) = run(&[std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| "atrium".into()), "down".into(), self.cfg_path()], Duration::from_secs(60)); (c == 0, t) }
            ["restart", room] if yes => self.restart_room(room),
            ["restart-anchor", name] if yes => match self.machine(name) { Ok(m) => { let (c, t) = remote(m, "restart-anchor"); (c == 0, t) } Err(e) => (false, e) },
            ["down"] | ["restart", _] | ["restart-anchor", _] => (false, "refused: add --yes to confirm".into()),
            _ => (false, format!("not an allowed fleet verb.\n{USAGE}")),
        };
        if !matches!(a.as_slice(), ["status"] | ["alarms"]) || !ok { self.record(&a.join(" "), ok, &text); }
        (ok, text)
    }

    fn cfg_path(&self) -> String { std::env::var("ATRIUM_CONFIG").unwrap_or_else(|_| "D:/ATRIUM/ops/atrium.toml".into()) }

    fn restart_room(&self, room: &str) -> (bool, String) {
        let Some(r) = self.cfg.room.iter().find(|r| r.name == room) else { return (false, format!("unknown room {room:?}")) };
        if r.kind != crate::Kind::Managed {
            return match external_task(r) {
                Some(task) => {
                    let (c, t) = run(&["schtasks".into(), "/Run".into(), "/TN".into(), task.clone()], Duration::from_secs(15));
                    (c == 0, if c == 0 { format!("{room}: started its task {task:?}") } else { format!("{room}: schtasks /Run {task:?} failed: {}", t.trim()) })
                }
                None => (false, format!("{room} is external with no `task` configured; not restartable from fleet")),
            };
        }
        let pids: std::collections::BTreeMap<String, u32> = fs::read(self.cfg.state.join("pids.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let Some(pid) = pids.get(room) else { return (false, format!("{room} has no live pid (is atrium up?)")) };
        crate::tree::kill_tree_by_pid(*pid);
        (true, format!("{room} (pid {pid}) stopped; atrium respawns it within a few seconds"))
    }

    fn status(&self) -> String {
        let mut out = String::new();
        match Status::load(&self.cfg.state) {
            Ok(s) if s.live(Duration::from_secs(10)) => {
                let down: Vec<String> = s.rooms.iter().filter(|(_, r)| r.health != Health::Up).map(|(n, _)| n.clone()).collect();
                let restarts: u64 = s.rooms.values().map(|r| r.restarts).sum();
                out += &format!("xing-pc: atrium UP, {} rooms, {} down{}, restarts {}, chain seq {}\n", s.rooms.len(), down.len(), if down.is_empty() { String::new() } else { format!(" ({})", down.join(", ")) }, restarts, s.chain_seq);
            }
            Ok(_) => out += "xing-pc: atrium DOWN (no live supervisor)\n",
            Err(e) => out += &format!("xing-pc: atrium status unreadable: {e}\n"),
        }
        for m in self.fc.machine.iter().filter(|m| m.ssh.is_some()) {
            if !reachable(&m.host) { out += &format!("{}: OFFLINE (asleep or off){}\n", m.name, if m.mac.is_some() { "; try wake" } else { "" }); continue; }
            let (c, t) = remote(m, "status");
            out += &format!("{}: {}\n", m.name, if c == 0 { t.replace('\n', " | ") } else { format!("reachable, status failed: {}", t.lines().next().unwrap_or("")) });
        }
        out.trim_end().to_string()
    }
}

/// The task to start for an external room: only a plain task name from config
/// (letters, digits, '-', '_', '\\'), so chat text can never reach schtasks.
pub fn external_task(r: &crate::Room) -> Option<String> {
    let t = r.task.as_deref()?.trim();
    let ok = !t.is_empty() && t.len() <= 128 && t.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '\\'));
    ok.then(|| t.to_string())
}

// ---------------------------------------------------------------- telegram bot

/// Telegram's sendMessage limit is 4096 UTF-16 code units. Chunks are kept a
/// little under it, counted in chars (a char is at most 2 UTF-16 units, and
/// every char in our ops text is in the BMP; the margin covers the rest).
pub const TG_CHUNK_CHARS: usize = 3800;

/// Split `text` into pieces of at most `max` chars, never truncating. Cuts on
/// the last newline in the window, else the last sentence end (". ", "! ",
/// "? "), else the last space, else hard at `max` chars. Always on a char
/// boundary, so UTF-8 is never broken.
pub fn split_message(text: &str, max: usize) -> Vec<String> {
    let max = max.max(1);
    let mut out = Vec::new();
    let mut rest = text.trim_end();
    while !rest.is_empty() {
        // Byte index just past the first `max` chars (or the whole rest).
        let end = rest.char_indices().nth(max).map(|(i, _)| i).unwrap_or(rest.len());
        if end == rest.len() { out.push(rest.to_string()); break; }
        let win = &rest[..end];
        let min_cut = win.len() / 3; // never emit a tiny head piece
        let cut = win.rfind('\n').filter(|&i| i >= min_cut).map(|i| i + 1)
            .or_else(|| [". ", "! ", "? "].iter().filter_map(|p| win.rfind(p)).max().filter(|&i| i >= min_cut).map(|i| i + 2))
            .or_else(|| win.rfind(' ').filter(|&i| i >= min_cut).map(|i| i + 1))
            .unwrap_or(end);
        let piece = rest[..cut].trim_end();
        if !piece.is_empty() { out.push(piece.to_string()); }
        rest = rest[cut..].trim_start_matches(['\n', ' ']);
    }
    if out.is_empty() { out.push(String::new()); }
    out
}

fn tg_env(p: &std::path::Path) -> Result<(String, i64), String> {
    let t = fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let get = |k: &str| t.lines().find_map(|l| l.strip_prefix(&format!("{k}=")).map(|v| v.trim().to_string()));
    let tok = get("TELEGRAM_BOT_TOKEN").ok_or("TELEGRAM_BOT_TOKEN missing")?;
    let chat = get("TELEGRAM_CHAT_ID").ok_or("TELEGRAM_CHAT_ID missing")?.parse::<i64>().map_err(|e| format!("TELEGRAM_CHAT_ID: {e}"))?;
    Ok((tok, chat))
}

/// curl with its config on stdin, so the token never shows on a command line.
fn tg_call(tok: &str, method: &str, fields: &[(&str, String)], timeout_s: u64) -> Result<serde_json::Value, String> {
    use std::io::Write;
    let mut cfg = format!("url = \"https://api.telegram.org/bot{tok}/{method}\"\nsilent\nmax-time = {timeout_s}\n");
    for (k, v) in fields { cfg += &format!("data-urlencode = \"{k}={}\"\n", v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")); }
    let mut c = Command::new("curl").args(["-K", "-"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|e| format!("curl: {e}"))?;
    if let Some(mut si) = c.stdin.take() { si.write_all(cfg.as_bytes()).map_err(|e| e.to_string())?; }
    let out = c.wait_with_output().map_err(|e| e.to_string())?;
    serde_json::from_slice(&out.stdout).map_err(|e| format!("telegram reply: {e}"))
}

/// Send `text` as one or more messages (split, never cut). Multi-part
/// messages get a "(i/n)" suffix so the phone shows they belong together.
fn tg_send(tok: &str, chat: i64, text: &str) {
    let parts = split_message(text, TG_CHUNK_CHARS);
    let n = parts.len();
    for (i, p) in parts.into_iter().enumerate() {
        let body = if n > 1 { format!("{p}\n({}/{n})", i + 1) } else { p };
        if let Err(e) = tg_call(tok, "sendMessage", &[("chat_id", chat.to_string()), ("text", body)], 15) { eprintln!("fleet bot: sendMessage part {}/{n}: {e}", i + 1); }
    }
}

/// Map a chat message to fleet args. Destructive verbs need a trailing "yes".
pub fn parse_command(text: &str) -> Option<Vec<String>> {
    let mut w: Vec<String> = text.split_whitespace().map(|s| s.trim_start_matches('/').split('@').next().unwrap_or("").to_lowercase()).collect();
    if w.is_empty() { return None; }
    if w[0] == "restart_anchor" { w[0] = "restart-anchor".into(); }
    if w.last().map(|s| s == "yes").unwrap_or(false) { w.pop(); w.push("--yes".into()); }
    match w[0].as_str() { "status" | "alarms" | "wake" | "up" | "down" | "restart" | "restart-anchor" => Some(w), _ => None }
}

/// New unauthorized hits in xing-pc-mcp's audit chain since the last call.
/// Read-only on the audit file. The cursor is a byte offset kept in
/// `cursor_file`: the first run starts at the end (no flood of history), a
/// file that shrank (rotated) restarts at 0, and only whole lines are taken.
pub fn mcp_audit_alerts(audit: &std::path::Path, cursor_file: &std::path::Path) -> Vec<String> {
    // Filter on the FULL line (the ua field sits at the end, past any display cut), then truncate.
    tail_new_full(audit, cursor_file).into_iter()
        .filter(|l| l.contains("unauthorized") && !is_own_probe(l))
        .map(|l| l.chars().take(300).collect())
        .collect()
}

/// Our own funnel watchdog (xing-pc-mcp\funnel-watchdog.ps1) probes /mcp every
/// 5 min without a token on purpose (a 401 proves the endpoint is alive). Those
/// hits stay in the audit chain; they just don't page the phone.
pub const OWN_PROBE_UA: &str = "atrium-funnel-watchdog/";
fn is_own_probe(line: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(line).ok()
        .and_then(|v| v["ua"].as_str().map(|u| u.starts_with(OWN_PROBE_UA)))
        .unwrap_or(false)
}

/// Every new whole line of `file` since the cursor (same cursor rules as above).
pub fn tail_new(file: &std::path::Path, cursor_file: &std::path::Path) -> Vec<String> {
    tail_new_full(file, cursor_file).into_iter().map(|l| l.chars().take(300).collect()).collect()
}

/// Same cursor rules as `tail_new`, but whole lines, untruncated.
pub fn tail_new_full(file: &std::path::Path, cursor_file: &std::path::Path) -> Vec<String> {
    let Ok(bytes) = fs::read(file) else { return Vec::new() };
    let len = bytes.len() as u64;
    let cur = match fs::read_to_string(cursor_file).ok().and_then(|s| s.trim().parse::<u64>().ok()) {
        Some(c) if c <= len => c,
        Some(_) => 0,
        None => { let _ = fs::write(cursor_file, len.to_string()); return Vec::new(); }
    };
    let tail = &bytes[cur as usize..];
    let Some(end) = tail.iter().rposition(|b| *b == b'\n').map(|i| i + 1) else { return Vec::new() };
    let _ = fs::write(cursor_file, (cur + end as u64).to_string());
    String::from_utf8_lossy(&tail[..end]).lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect()
}

/// Every command the bot obeys, in menu order. This one list feeds the
/// Telegram "/" popup, the menu button list, and /help, so they never drift.
pub const BOT_COMMANDS: &[(&str, &str)] = &[
    ("status", "All machines: rooms, chain seq, peers"),
    ("alarms", "Tamper alarms from the mini watcher"),
    ("wake", "Wake a machine: /wake mini or /wake laptop"),
    ("up", "Start the atrium supervisor"),
    ("down", "Stop atrium: /down yes"),
    ("restart", "Restart a room: /restart <room> yes"),
    ("restart_anchor", "Restart an anchor: /restart_anchor mini yes"),
    ("help", "Show every command"),
];

fn commands_json() -> String {
    serde_json::Value::Array(BOT_COMMANDS.iter().map(|(c, d)| serde_json::json!({ "command": c, "description": d })).collect()).to_string()
}

/// Menu button: the Mini App when an https URL is configured, else the command list.
pub fn menu_button(url: Option<&str>) -> String {
    match url {
        Some(u) if u.starts_with("https://") => serde_json::json!({ "type": "web_app", "text": "ATRIUM", "web_app": { "url": u } }).to_string(),
        _ => serde_json::json!({ "type": "commands" }).to_string(),
    }
}

fn bot_help() -> String {
    let mut s = String::from("ATRIUM fleet\n");
    for (c, d) in BOT_COMMANDS { s += &format!("/{c} - {d}\n"); }
    s
}

impl Fleet {
    /// Long-poll loop. Only TELEGRAM_CHAT_ID is obeyed; anything else is
    /// ignored and recorded. Commands go through `exec`, so the bot can never
    /// do more than the CLI allowlist.
    pub fn bot(&self) -> i32 {
        let Some(envp) = self.fc.telegram_env.clone() else { eprintln!("fleet bot: set [fleet] telegram_env"); return 2 };
        let (tok, chat) = match tg_env(&envp) { Ok(v) => v, Err(e) => { eprintln!("fleet bot: {e}"); return 2 } };
        let _ = fs::create_dir_all(&self.dir);
        let offp = self.dir.join("bot-offset");
        let mut offset: i64 = fs::read_to_string(&offp).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
        // Full list for the "/" popup, both globally and pinned to Xing's chat
        // (a chat-scoped list wins over any stale default one).
        let cmds = commands_json();
        for scope in [r#"{"type":"default"}"#.to_string(), format!(r#"{{"type":"chat","chat_id":{chat}}}"#)] {
            if let Err(e) = tg_call(&tok, "setMyCommands", &[("commands", cmds.clone()), ("scope", scope)], 15) { eprintln!("fleet bot: setMyCommands: {e}"); }
        }
        if let Err(e) = tg_call(&tok, "setChatMenuButton", &[("chat_id", chat.to_string()), ("menu_button", menu_button(self.fc.miniapp_url.as_deref()))], 15) { eprintln!("fleet bot: setChatMenuButton: {e}"); }
        eprintln!("fleet bot: polling (offset {offset})");
        loop {
            let r = match tg_call(&tok, "getUpdates", &[("offset", offset.to_string()), ("timeout", "25".into()), ("allowed_updates", r#"["message"]"#.into())], 35) {
                Ok(v) => v,
                Err(e) => { eprintln!("fleet bot: {e}"); std::thread::sleep(Duration::from_secs(5)); continue; }
            };
            for u in r["result"].as_array().cloned().unwrap_or_default() {
                offset = u["update_id"].as_i64().unwrap_or(offset) + 1;
                let _ = fs::write(&offp, offset.to_string());
                let from = u["message"]["chat"]["id"].as_i64().unwrap_or(0);
                let text = u["message"]["text"].as_str().unwrap_or("").to_string();
                if from != chat { self.record(&format!("bot: ignored chat {from}"), false, &text); continue; }
                let reply = match parse_command(&text) {
                    Some(args) => { let (ok, t) = self.exec(&args); format!("{} {}\n{}", if ok { "OK" } else { "FAILED" }, args.join(" "), t) }
                    None => bot_help(),
                };
                tg_send(&tok, chat, &reply);
            }
            // Between polls (~25 s): push new bad-token hits on the public endpoint.
            if let Some(a) = &self.fc.mcp_audit {
                let hits = mcp_audit_alerts(a, &self.dir.join("mcp-audit-cursor"));
                if !hits.is_empty() {
                    let mut msg = format!("ALERT xing-pc-mcp: {} unauthorized request(s) on the public /mcp endpoint\n", hits.len());
                    for h in hits.iter().take(5) { msg += h; msg.push('\n'); }
                    tg_send(&tok, chat, &msg);
                    self.record("alert: mcp unauthorized", false, &msg);
                }
            }
            // Agent reports (charter goal 0: keep Xing in the loop). Whole lines,
            // every one of them: long reports are split across messages, never cut.
            if let Some(o) = &self.fc.agent_outbox {
                let lines = tail_new_full(o, &self.dir.join("agent-outbox-cursor"));
                if !lines.is_empty() {
                    let mut msg = String::from("ATRIUM agent\n");
                    for l in &lines { msg += l; msg.push('\n'); }
                    tg_send(&tok, chat, &msg);
                    self.record("agent report", true, &msg);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commands_map_to_the_allowlist_only() {
        assert_eq!(parse_command("/status"), Some(vec!["status".to_string()]));
        assert_eq!(parse_command("/restart loop yes"), Some(vec!["restart".into(), "loop".into(), "--yes".into()]));
        let room = |t: &str| -> crate::Room { toml::from_str(&format!("name = \"x\"\n{t}")).unwrap() };
        assert_eq!(super::external_task(&room("task = \"ductei-sync-serve\"")), Some("ductei-sync-serve".into()));
        assert_eq!(super::external_task(&room("task = \"a & calc\"")), None);
        assert_eq!(super::external_task(&room("task = \"x\\\" /F\"")), None);
        assert_eq!(super::external_task(&room("")), None);
        assert_eq!(parse_command("/restart_anchor@atrium_bot mini yes"), Some(vec!["restart-anchor".into(), "mini".into(), "--yes".into()]));
        assert_eq!(parse_command("rm -rf /"), None);
        assert_eq!(parse_command("/bash ls"), None);
    }

    #[test]
    fn long_messages_split_on_boundaries_and_lose_nothing() {
        assert_eq!(split_message("short", 100), vec!["short".to_string()]);
        // Sentence boundary wins when there is no newline.
        let s = "Only report what changed. ".repeat(40);
        let parts = split_message(&s, 100);
        assert!(parts.len() > 1);
        for p in &parts { assert!(p.chars().count() <= 100, "{p:?}"); assert!(p.ends_with('.'), "cut mid-sentence: {p:?}"); }
        let joined: String = parts.join(" ");
        assert_eq!(joined.split_whitespace().count(), s.split_whitespace().count());
        // Newlines are preferred.
        let lines: String = (0..50).map(|i| format!("line {i} ok\n")).collect();
        for p in split_message(&lines, 64) { assert!(p.starts_with("line ") && p.ends_with("ok"), "{p:?}"); }
        // Multibyte text with no spaces: hard cut, still valid UTF-8 and complete.
        let e = "é😀".repeat(500);
        let parts = split_message(&e, 333);
        assert!(parts.iter().all(|p| p.chars().count() <= 333));
        assert_eq!(parts.concat(), e);
        // Real limit: a 10k report fits Telegram per piece.
        let big = "word ".repeat(2000);
        assert!(split_message(&big, TG_CHUNK_CHARS).iter().all(|p| p.encode_utf16().count() <= 4096));
    }

    #[test]
    fn agent_outbox_lines_are_not_truncated() {
        let d = std::env::temp_dir().join(format!("atrium-outbox-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let (o, c) = (d.join("outbox.jsonl"), d.join("cursor"));
        fs::write(&o, "").unwrap();
        assert!(tail_new_full(&o, &c).is_empty());
        let long = format!("[ops-1] {} and unload done.", "x".repeat(900));
        fs::write(&o, format!("{long}\n")).unwrap();
        assert_eq!(tail_new_full(&o, &c), vec![long]);
    }

    #[test]
    fn bot_menu_lists_every_verb_and_only_valid_names() {
        let names: Vec<&str> = BOT_COMMANDS.iter().map(|(c, _)| *c).collect();
        for v in ["status", "alarms", "wake", "up", "down", "restart", "restart_anchor", "help"] { assert!(names.contains(&v), "menu missing /{v}"); }
        for (c, d) in BOT_COMMANDS {
            assert!(!c.is_empty() && c.len() <= 32 && c.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_'), "bad telegram command name {c}");
            assert!(!d.is_empty() && d.len() <= 256);
            if *c != "help" { assert!(parse_command(&format!("/{c}")).is_some(), "/{c} in menu but not obeyed"); }
        }
        let v: serde_json::Value = serde_json::from_str(&commands_json()).unwrap();
        assert_eq!(v.as_array().unwrap().len(), BOT_COMMANDS.len());
        assert!(bot_help().contains("/restart_anchor"));
    }

    #[test]
    fn menu_button_only_opens_https_mini_apps() {
        assert!(menu_button(Some("https://x.ts.net/atrium/")).contains("web_app"));
        assert!(menu_button(Some("http://x/")).contains("\"commands\""));
        assert!(menu_button(None).contains("\"commands\""));
    }

    #[test]
    fn mcp_audit_alerts_start_at_end_then_report_only_new_unauthorized() {
        let d = std::env::temp_dir().join(format!("atrium-mcp-audit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let (a, c) = (d.join("audit.chain.jsonl"), d.join("cursor"));
        fs::write(&a, "{\"event\":\"unauthorized\",\"remote\":\"old\"}\n").unwrap();
        assert!(mcp_audit_alerts(&a, &c).is_empty(), "first run skips history");
        let mut f = fs::OpenOptions::new().append(true).open(&a).unwrap();
        std::io::Write::write_all(&mut f, b"{\"event\":\"tool\"}\n{\"event\":\"unauthorized\",\"remote\":\"1.2.3.4\"}\n{\"event\":\"unauth").unwrap();
        let hits = mcp_audit_alerts(&a, &c);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].contains("1.2.3.4"));
        assert!(mcp_audit_alerts(&a, &c).is_empty(), "partial line waits; nothing repeats");
        fs::write(&a, "{\"event\":\"gpu_unauthorized\"}\n").unwrap();
        assert_eq!(mcp_audit_alerts(&a, &c).len(), 1, "rotated file restarts at 0");
        let mut f = fs::OpenOptions::new().append(true).open(&a).unwrap();
        std::io::Write::write_all(&mut f, b"{\"event\":\"unauthorized\",\"ua\":\"atrium-funnel-watchdog/1\"}\n{\"event\":\"unauthorized\",\"ua\":\"curl/8\"}\n").unwrap();
        let hits = mcp_audit_alerts(&a, &c);
        assert_eq!(hits.len(), 1, "own watchdog probe is skipped, others page: {hits:?}");
        assert!(hits[0].contains("curl/8"));
        // Real-shaped line: ua past char 300 (this is what slipped through before).
        let pad = "a".repeat(330);
        let real = format!("{{\"event\":\"unauthorized\",\"hash\":\"{pad}\",\"ua\":\"atrium-funnel-watchdog/1\"}}\n");
        let mut f = fs::OpenOptions::new().append(true).open(&a).unwrap();
        std::io::Write::write_all(&mut f, real.as_bytes()).unwrap();
        assert!(mcp_audit_alerts(&a, &c).is_empty(), "long own-probe line must be skipped");
    }
}
