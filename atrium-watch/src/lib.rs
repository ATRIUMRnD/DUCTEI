// Copyright (C) 2026 xingxerx
// Licensed under the Apache License 2.0. See the LICENSE file in the repository root.

//! atrium-watch: the live witness. Runs on an anchor peer next to
//! `ductei-sync serve`, follows its accepted.jsonl as it grows, and raises an
//! alarm the moment the anchors stop making sense:
//!
//! - ROLLBACK: a signer's seq went backwards (log cut and rewritten).
//! - FORK: same seq, different head (history rewritten in place).
//! - BAD_SIG: anchor not signed by the pinned key for its stream.
//! - UNKNOWN_SIGNER: anchor from a key nobody pinned.
//! - SILENT: a stream sent nothing for `silence_secs` (source down or muzzled).
//! - SOURCE_ALARM: the source itself reported tamper (atrium self-check).
//! - PEER_LOG_SHRANK: the peer's own accepted.jsonl got shorter.
//!
//! Every alarm gets a category (QFLTL severity): TAMPER is always sent, loud,
//! never cooled down; HEALTH is sent silently; RECOVERY edits the matching
//! SILENT message in place instead of pinging again. Unknown kinds fail loud.
//!
//! State (offset + last seq/head per stream) persists, so a restart never
//! forgets what it saw and never re-alarms on old lines.

use ductei_core::Envelope;
use ductei_mcp::{Anchor, Scheme};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// The peer's accepted.jsonl (written by ductei-sync serve).
    pub inbound: PathBuf,
    /// Where alarms and persisted state go.
    pub dir: PathBuf,
    #[serde(default = "d_poll")]
    pub poll_ms: u64,
    #[serde(default)]
    pub stream: Vec<StreamCfg>,
    #[serde(default)]
    pub alert: AlertCfg,
}
fn d_poll() -> u64 { 250 }

#[derive(Debug, Clone, Deserialize)]
pub struct StreamCfg {
    pub name: String,
    /// Raw public key file (gate-ml-dsa-65.pk) copied from the source.
    pub pubkey: PathBuf,
    #[serde(default = "d_scheme")]
    pub scheme: String,
    /// Alarm if nothing arrives for this long. 0 = off.
    #[serde(default)]
    pub silence_secs: u64,
}
fn d_scheme() -> String { "ml-dsa-65".into() }

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AlertCfg {
    /// Command run per alarm, message appended as the last argument.
    #[serde(default)]
    pub cmd: Vec<String>,
    /// File with TELEGRAM_BOT_TOKEN=... and TELEGRAM_CHAT_ID=... lines (owner-only ACL).
    #[serde(default)]
    pub telegram_env: Option<PathBuf>,
    /// Same kind of alarm for the same stream goes out at most once per this.
    /// TAMPER is exempt: it always goes out.
    #[serde(default = "d_cool")]
    pub cooldown_secs: u64,
    /// Optional forum-group topics: category label (TAMPER, HEALTH, ...) -> message_thread_id.
    #[serde(default)]
    pub topics: BTreeMap<String, i64>,
}
fn d_cool() -> u64 { 60 }

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Last { pub seq: u64, pub head: String, pub unix: u64 }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State { pub offset: u64, pub last: BTreeMap<String, Last> }

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Alarm { pub unix: u64, pub kind: String, pub stream: String, pub detail: String }

/// Alert severity, shared with fleet-bot so both speak the same categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cat { Tamper, Access, Health, Recovery, Ops }

impl Cat {
    pub fn label(self) -> &'static str {
        match self { Cat::Tamper => "TAMPER", Cat::Access => "ACCESS", Cat::Health => "HEALTH", Cat::Recovery => "RECOVERY", Cat::Ops => "OPS" }
    }
    pub fn icon(self) -> &'static str {
        match self { Cat::Tamper => "\u{1F534}", Cat::Access => "\u{1F7E0}", Cat::Health => "\u{1F7E1}", Cat::Recovery => "\u{1F7E2}", Cat::Ops => "\u{1F535}" }
    }
    /// Loud categories ring the phone; the rest arrive silently.
    pub fn loud(self) -> bool { matches!(self, Cat::Tamper | Cat::Access) }
}

/// Map an alarm kind to its category. Anything unknown is treated as TAMPER,
/// so a new alarm kind can never be quietly downgraded.
pub fn category(kind: &str) -> Cat {
    match kind {
        "SILENT" | "DOWN" => Cat::Health,
        "RESUMED" => Cat::Recovery,
        "UNAUTHORIZED" => Cat::Access,
        "OPS" => Cat::Ops,
        _ => Cat::Tamper,
    }
}

pub fn now_unix() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }

fn short(s: &str) -> &str { &s[..s.len().min(16)] }

fn esc(s: &str) -> String { s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;") }

fn fmt_utc(u: u64) -> String { let s = u % 86400; format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60) }

/// Telegram HTML body: icon + category, kind, stream, detail, UTC time.
/// Built only from alarm fields, never from config, so no secret can leak in.
pub fn format_alert(a: &Alarm, cat: Cat) -> String {
    format!("{} <b>{}</b> \u{00B7} {}\n<code>{}</code> {}\n<i>{} UTC</i>", cat.icon(), cat.label(), esc(&a.kind), esc(&a.stream), esc(&a.detail), fmt_utc(a.unix))
}

struct Stream { cfg: StreamCfg, kid: String, pk: (Scheme, Vec<u8>), last_seen: Instant, silent: bool }

pub struct Watcher {
    cfg: Config,
    streams: Vec<Stream>,
    pub state: State,
    partial: String,
    cooldown: BTreeMap<(String, String), Instant>,
    /// Telegram message_id of the open SILENT alert per stream, for edit-on-resume.
    msg_ids: Arc<Mutex<BTreeMap<String, i64>>>,
}

impl Watcher {
    pub fn open(cfg: Config) -> Result<Self, String> {
        fs::create_dir_all(&cfg.dir).map_err(|e| format!("mkdir {}: {e}", cfg.dir.display()))?;
        let mut streams = Vec::new();
        for s in &cfg.stream {
            let pk = fs::read(&s.pubkey).map_err(|e| format!("{}: {e}", s.pubkey.display()))?;
            let scheme = Scheme::parse(&s.scheme).ok_or_else(|| format!("{}: unknown scheme {}", s.name, s.scheme))?;
            streams.push(Stream { kid: ductei_mcp::sha256_hex(&pk), pk: (scheme, pk), cfg: s.clone(), last_seen: Instant::now(), silent: false });
        }
        let state = fs::read(cfg.dir.join("watch-state.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        Ok(Self { cfg, streams, state, partial: String::new(), cooldown: BTreeMap::new(), msg_ids: Arc::new(Mutex::new(BTreeMap::new())) })
    }

    fn save(&self) {
        let p = self.cfg.dir.join("watch-state.json");
        let tmp = p.with_extension("tmp");
        if fs::write(&tmp, serde_json::to_vec(&self.state).unwrap_or_default()).is_ok() { let _ = fs::rename(&tmp, &p); }
    }

    /// Check one accepted.jsonl line. Returns the alarms it raises.
    pub fn check_line(&mut self, line: &str) -> Vec<Alarm> {
        let mut out = Vec::new();
        let Ok(env) = serde_json::from_str::<Envelope>(line) else { return out };
        let mk = |kind: &str, stream: &str, detail: String| Alarm { unix: now_unix(), kind: kind.into(), stream: stream.into(), detail };
        if env.key.contains("/alarm/") {
            let src = env.key.split('/').nth(1).unwrap_or("?").to_string();
            out.push(mk("SOURCE_ALARM", &src, String::from_utf8_lossy(&env.blob).into_owned()));
            return out;
        }
        let Ok(a) = serde_json::from_slice::<Anchor>(&env.blob) else { return out };
        let Some(i) = self.streams.iter().position(|s| s.kid == a.kid) else {
            out.push(mk("UNKNOWN_SIGNER", "?", format!("kid {} seq {} key {}", short(&a.kid), a.seq, env.key)));
            return out;
        };
        let name = self.streams[i].cfg.name.clone();
        if !a.verify(Some(&self.streams[i].pk)) {
            out.push(mk("BAD_SIG", &name, format!("seq {} head {}", a.seq, short(&a.head))));
            return out;
        }
        let s = &mut self.streams[i];
        s.last_seen = Instant::now();
        if s.silent { s.silent = false; out.push(mk("RESUMED", &name, format!("seq {}", a.seq))); }
        match self.state.last.get(&name) {
            Some(l) if a.seq < l.seq => out.push(mk("ROLLBACK", &name, format!("seq {} after seq {} (head {} -> {})", a.seq, l.seq, short(&l.head), short(&a.head)))),
            Some(l) if a.seq == l.seq && a.head != l.head => out.push(mk("FORK", &name, format!("seq {}: head {} then {}", a.seq, short(&l.head), short(&a.head)))),
            _ => {}
        }
        // Only move forward: a rollback must never become the new normal.
        let adv = self.state.last.get(&name).map(|l| a.seq > l.seq).unwrap_or(true);
        if adv { self.state.last.insert(name, Last { seq: a.seq, head: a.head.clone(), unix: now_unix() }); }
        out
    }

    pub fn check_silence(&mut self) -> Vec<Alarm> {
        let mut out = Vec::new();
        for s in &mut self.streams {
            if s.cfg.silence_secs > 0 && !s.silent && s.last_seen.elapsed() > Duration::from_secs(s.cfg.silence_secs) {
                s.silent = true;
                out.push(Alarm { unix: now_unix(), kind: "SILENT".into(), stream: s.cfg.name.clone(), detail: format!("no anchor for {}s", s.cfg.silence_secs) });
            }
        }
        out
    }

    /// Read whatever was appended since last time. Returns alarms.
    pub fn poll(&mut self) -> Vec<Alarm> {
        let mut out = Vec::new();
        let len = fs::metadata(&self.cfg.inbound).map(|m| m.len()).unwrap_or(0);
        if len < self.state.offset {
            out.push(Alarm { unix: now_unix(), kind: "PEER_LOG_SHRANK".into(), stream: "peer".into(), detail: format!("{} was {} bytes, now {}", self.cfg.inbound.display(), self.state.offset, len) });
            // Resume at the new end: re-reading old lines against the saved
            // seq/head would flood false ROLLBACK alarms. The shrink is the alarm.
            self.state.offset = len;
            self.partial.clear();
            self.save();
        }
        if len > self.state.offset {
            if let Ok(mut f) = fs::File::open(&self.cfg.inbound) {
                let mut buf = String::new();
                if f.seek(SeekFrom::Start(self.state.offset)).is_ok() && f.read_to_string(&mut buf).is_ok() {
                    self.state.offset += buf.len() as u64;
                    self.partial.push_str(&buf);
                    while let Some(nl) = self.partial.find('\n') {
                        let line: String = self.partial.drain(..=nl).collect();
                        let line = line.trim();
                        if !line.is_empty() { out.extend(self.check_line(line)); }
                    }
                    self.save();
                }
            }
        }
        out.extend(self.check_silence());
        out
    }

    /// Every alarm lands in alarms.jsonl with its category; outward alerts
    /// honor the cooldown, except TAMPER which always goes out.
    pub fn raise(&mut self, a: &Alarm) {
        let cat = category(&a.kind);
        #[derive(Serialize)]
        struct Logged<'x> { #[serde(flatten)] a: &'x Alarm, cat: &'static str }
        let line = serde_json::to_string(&Logged { a, cat: cat.label() }).unwrap_or_default();
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(self.cfg.dir.join("alarms.jsonl")) { let _ = writeln!(f, "{line}"); let _ = f.sync_all(); }
        eprintln!("atrium-watch: [{}] {} {} {}", cat.label(), a.kind, a.stream, a.detail);
        if cat != Cat::Tamper {
            let k = (a.kind.clone(), a.stream.clone());
            if let Some(t) = self.cooldown.get(&k) { if t.elapsed() < Duration::from_secs(self.cfg.alert.cooldown_secs) { return; } }
            self.cooldown.insert(k, Instant::now());
        }
        let msg = format!("ATRIUM [{}] {}: {} {}", cat.label(), a.kind, a.stream, a.detail);
        if !self.cfg.alert.cmd.is_empty() {
            let _ = std::process::Command::new(&self.cfg.alert.cmd[0]).args(&self.cfg.alert.cmd[1..]).arg(&msg).spawn();
        }
        if let Some(p) = &self.cfg.alert.telegram_env {
            let edit = if cat == Cat::Recovery { self.msg_ids.lock().ok().and_then(|mut m| m.remove(&a.stream)) } else { None };
            let record = (a.kind == "SILENT").then(|| (self.msg_ids.clone(), a.stream.clone()));
            let thread = self.cfg.alert.topics.get(cat.label()).copied();
            send_telegram(p, &format_alert(a, cat), cat, thread, edit, record);
        }
    }

    pub fn poll_ms(&self) -> u64 { self.cfg.poll_ms }
}

/// Quote a value for a curl config file string.
fn curl_q(s: &str) -> String { s.replace('\\', "\\\\").replace('"', "\\\"").replace('\r', "").replace('\n', "\\n") }

/// curl config text. The token appears only in the url line, which curl reads
/// from stdin, so it never lands on a command line or in the process list.
fn telegram_cfg(tok: &str, method: &str, fields: &[(&str, String)]) -> String {
    let mut s = format!("url = \"https://api.telegram.org/bot{}/{method}\"\n", curl_q(tok));
    for (k, v) in fields { s.push_str(&format!("data-urlencode = \"{k}={}\"\n", curl_q(v))); }
    s.push_str("silent\nmax-time = 10\n");
    s
}

type MsgIds = Arc<Mutex<BTreeMap<String, i64>>>;

/// Telegram via curl, so no TLS stack lives in this binary.
fn send_telegram(env: &Path, html: &str, cat: Cat, thread: Option<i64>, edit: Option<i64>, record: Option<(MsgIds, String)>) {
    let Ok(t) = fs::read_to_string(env) else { return };
    let get = |k: &str| t.lines().find_map(|l| l.strip_prefix(&format!("{k}=")).map(|v| v.trim().to_string()));
    let (Some(tok), Some(chat)) = (get("TELEGRAM_BOT_TOKEN"), get("TELEGRAM_CHAT_ID")) else { return };
    let mut f: Vec<(&str, String)> = vec![("chat_id", chat), ("text", html.to_string()), ("parse_mode", "HTML".into())];
    let method = match edit {
        Some(id) => { f.push(("message_id", id.to_string())); "editMessageText" }
        None => {
            if !cat.loud() { f.push(("disable_notification", "true".into())); }
            if let Some(th) = thread { f.push(("message_thread_id", th.to_string())); }
            "sendMessage"
        }
    };
    let cfgtxt = telegram_cfg(&tok, method, &f);
    let child = std::process::Command::new("curl").args(["-K", "-"])
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn();
    if let Ok(mut c) = child {
        if let Some(mut si) = c.stdin.take() { let _ = si.write_all(cfgtxt.as_bytes()); }
        std::thread::spawn(move || {
            let Ok(out) = c.wait_with_output() else { return };
            let Some((ids, stream)) = record else { return };
            let id = serde_json::from_slice::<serde_json::Value>(&out.stdout).ok().and_then(|v| v["result"]["message_id"].as_i64());
            if let Some(id) = id {
                if let Ok(mut m) = ids.lock() { m.insert(stream, id); };
            };
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(key: &str, a: &Anchor) -> String {
        serde_json::to_string(&ductei_core::scoped(key, &["mcp:atrium:anchor"], [0; 16], a.seq + 1, &serde_json::to_vec(a).unwrap())).unwrap()
    }

    fn unsigned_watcher(dir: &Path) -> (Watcher, String) {
        // An unsigned stream: scheme none has no key, so test the ordering rules
        // through a stream whose kid matches and verify() accepts (pk None path is
        // not reachable from config), by driving check_line on a hand-built state.
        let cfg = Config { inbound: dir.join("in.jsonl"), dir: dir.to_path_buf(), poll_ms: 10, stream: vec![], alert: AlertCfg::default() };
        (Watcher::open(cfg).unwrap(), String::new())
    }

    #[test]
    fn unknown_signer_and_source_alarm() {
        let d = std::env::temp_dir().join(format!("aw-{}", now_unix() ^ std::process::id() as u64));
        let (mut w, _) = unsigned_watcher(&d);
        let a = Anchor { v: 2, kid: "ab".repeat(32), seq: 5, head: "cd".repeat(32), scheme: "ml-dsa-65".into(), sig: Some("x".into()) };
        assert_eq!(w.check_line(&line("mcp/atrium/anchor/5", &a))[0].kind, "UNKNOWN_SIGNER");
        let al = serde_json::to_string(&ductei_core::scoped("mcp/atrium/alarm/9", &["mcp:atrium:anchor"], [0; 16], 1, b"chain broken")).unwrap();
        let r = w.check_line(&al);
        assert_eq!((r[0].kind.as_str(), r[0].stream.as_str(), r[0].detail.as_str()), ("SOURCE_ALARM", "atrium", "chain broken"));
    }

    #[test]
    fn shrink_is_caught_and_state_persists() {
        let d = std::env::temp_dir().join(format!("aw2-{}", now_unix() ^ std::process::id() as u64));
        fs::create_dir_all(&d).unwrap();
        let (mut w, _) = unsigned_watcher(&d);
        fs::write(d.join("in.jsonl"), "{}\n{}\n").unwrap();
        assert!(w.poll().is_empty());
        let (mut w2, _) = unsigned_watcher(&d);
        assert_eq!(w2.state.offset, 6, "offset persisted");
        fs::write(d.join("in.jsonl"), "{}\n").unwrap();
        let r = w2.poll();
        assert_eq!((r.len(), r[0].kind.as_str()), (1, "PEER_LOG_SHRANK"));
        assert_eq!(w2.state.offset, 3, "resumes at new end, no replay");
        fs::write(d.join("in.jsonl"), "{}\n{}\n").unwrap();
        assert!(w2.poll().is_empty(), "only new lines are read after a shrink");
    }

    #[test]
    fn categories_fail_loud() {
        for k in ["ROLLBACK", "FORK", "BAD_SIG", "UNKNOWN_SIGNER", "SOURCE_ALARM", "PEER_LOG_SHRANK", "SOME_NEW_KIND"] {
            assert_eq!(category(k), Cat::Tamper, "{k}");
        }
        assert_eq!(category("SILENT"), Cat::Health);
        assert_eq!(category("DOWN"), Cat::Health);
        assert_eq!(category("RESUMED"), Cat::Recovery);
        assert_eq!(category("UNAUTHORIZED"), Cat::Access);
        assert_eq!(category("OPS"), Cat::Ops);
        assert!(Cat::Tamper.loud() && Cat::Access.loud() && !Cat::Health.loud() && !Cat::Recovery.loud() && !Cat::Ops.loud());
    }

    #[test]
    fn alert_html_is_escaped() {
        let a = Alarm { unix: 3661, kind: "FORK".into(), stream: "<x>".into(), detail: "a&b \"c\"".into() };
        let h = format_alert(&a, Cat::Tamper);
        assert!(h.contains("&lt;x&gt;") && h.contains("a&amp;b") && h.contains("01:01:01 UTC") && h.contains("TAMPER"));
        assert!(!h.contains("<x>"));
    }

    #[test]
    fn curl_cfg_escapes_and_keeps_token_in_url_only() {
        let c = telegram_cfg("123:SECRET", "sendMessage", &[("chat_id", "9".into()), ("text", "say \"hi\"\nline2 \\".into())]);
        assert_eq!(c.matches("SECRET").count(), 1);
        assert!(c.lines().next().unwrap().contains("SECRET"));
        assert!(c.contains("text=say \\\"hi\\\"\\nline2 \\\\"));
        assert_eq!(c.lines().count(), 5, "embedded newline must not split the config");
    }

    #[test]
    fn raise_logs_category_and_tamper_skips_cooldown() {
        let d = std::env::temp_dir().join(format!("aw3-{}", now_unix() ^ std::process::id() as u64));
        let (mut w, _) = unsigned_watcher(&d);
        w.cfg.alert.cooldown_secs = 3600;
        let a = Alarm { unix: 1, kind: "BAD_SIG".into(), stream: "atrium".into(), detail: "seq 1".into() };
        w.raise(&a);
        w.raise(&a);
        assert!(w.cooldown.is_empty(), "TAMPER never enters the cooldown map");
        let h = Alarm { unix: 1, kind: "SILENT".into(), stream: "atrium".into(), detail: "no anchor".into() };
        w.raise(&h);
        assert_eq!(w.cooldown.len(), 1);
        let t = fs::read_to_string(d.join("alarms.jsonl")).unwrap();
        assert_eq!(t.matches("\"cat\":\"TAMPER\"").count(), 2);
        assert_eq!(t.matches("\"cat\":\"HEALTH\"").count(), 1);
    }
}
