//! atrium-keepalive: link detector room.
//!
//! Probes each target with a TCP connect every `--every` seconds (no ICMP, so
//! no raw sockets and no admin). Writes `status.json` atomically every round
//! (atrium's fresh_file) and appends to `events.jsonl` only on an up/down
//! change plus one summary per `--summary` rounds, so the log stays small.
//!
//! Diagnosis per round, from the target roles:
//!   lan down               -> "lan" (router / cable / adapter)
//!   wan down + lan up      -> "wan" (Starlink / ISP)
//!   only peer down         -> "peer" (that machine is off, asleep or offline)
//!
//! usage: atrium-keepalive --dir <dir> [--every 5] [--summary 60] [--timeout-ms 1500]
//!        --target <role>:<name>=<host:port> ...   (role = peer | lan | wan)

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone)]
struct Target { role: String, name: String, addr: String }

#[derive(Default)]
struct Tally { ok: u64, fail: u64, up: Option<bool>, last_ms: Option<u64> }

type Parsed = (PathBuf, u64, u64, u64, Vec<Target>);

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }

fn probe(addr: &str, timeout: Duration) -> Option<u64> {
    let sa: SocketAddr = addr.to_socket_addrs().ok()?.next()?;
    let t = Instant::now();
    TcpStream::connect_timeout(&sa, timeout).ok().map(|_| t.elapsed().as_millis() as u64)
}

fn publish(dir: &Path, name: &str, v: &serde_json::Value) -> std::io::Result<()> {
    let tmp = dir.join(format!("{name}.part"));
    fs::write(&tmp, serde_json::to_vec_pretty(v).unwrap_or_default())?;
    fs::rename(tmp, dir.join(name))
}

fn append(dir: &Path, v: &serde_json::Value) {
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(dir.join("events.jsonl")) {
        let _ = writeln!(f, "{v}");
    }
}

fn diagnose(round: &BTreeMap<String, (String, bool)>) -> &'static str {
    let any_down = |role: &str| round.values().any(|(r, u)| r == role && !*u);
    if any_down("lan") { "lan" } else if any_down("wan") { "wan" } else if any_down("peer") { "peer" } else { "ok" }
}

fn parse(args: &[String]) -> Result<Parsed, String> {
    let (mut dir, mut every, mut summary, mut tmo, mut targets) = (None, 5u64, 60u64, 1500u64, Vec::new());
    let mut i = 0;
    while i < args.len() {
        let v = args.get(i + 1).ok_or_else(|| format!("{} needs a value", args[i]))?;
        match args[i].as_str() {
            "--dir" => dir = Some(PathBuf::from(v)),
            "--every" => every = v.parse().map_err(|_| "--every wants seconds")?,
            "--summary" => summary = v.parse().map_err(|_| "--summary wants a round count")?,
            "--timeout-ms" => tmo = v.parse().map_err(|_| "--timeout-ms wants ms")?,
            "--target" => {
                let (rn, addr) = v.split_once('=').ok_or("--target wants role:name=host:port")?;
                let (role, name) = rn.split_once(':').ok_or("--target wants role:name=host:port")?;
                if !matches!(role, "peer" | "lan" | "wan") { return Err(format!("unknown role {role:?} (peer|lan|wan)")); }
                targets.push(Target { role: role.into(), name: name.into(), addr: addr.into() });
            }
            o => return Err(format!("unknown flag {o}")),
        }
        i += 2;
    }
    if targets.is_empty() { return Err("at least one --target".into()); }
    Ok((dir.ok_or("--dir is required")?, every.max(1), summary.max(1), tmo.max(100), targets))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (dir, every, summary, tmo, targets) = match parse(&args) {
        Ok(p) => p,
        Err(e) => { eprintln!("atrium-keepalive: {e}"); std::process::exit(64); }
    };
    if let Err(e) = fs::create_dir_all(&dir) { eprintln!("atrium-keepalive: {}: {e}", dir.display()); std::process::exit(73); }
    let timeout = Duration::from_millis(tmo);
    let mut tally: BTreeMap<String, Tally> = BTreeMap::new();
    let mut rounds = 0u64;
    let mut last_diag = "";
    let names: Vec<String> = targets.iter().map(|t| format!("{}:{}={}", t.role, t.name, t.addr)).collect();
    append(&dir, &serde_json::json!({"at": now(), "event": "start", "targets": names}));
    loop {
        let start = Instant::now();
        // Probe in parallel so one dead target cannot stretch the round.
        let handles: Vec<_> = targets.iter().cloned().map(|t| std::thread::spawn(move || { let r = probe(&t.addr, timeout); (t, r) })).collect();
        let mut round = BTreeMap::new();
        for h in handles {
            let Ok((t, r)) = h.join() else { continue };
            let up = r.is_some();
            let e = tally.entry(t.name.clone()).or_default();
            if up { e.ok += 1 } else { e.fail += 1 }
            e.last_ms = r;
            if e.up != Some(up) {
                append(&dir, &serde_json::json!({"at": now(), "event": if up {"up"} else {"down"}, "target": t.name, "role": t.role, "addr": t.addr, "rtt_ms": r}));
                e.up = Some(up);
            }
            round.insert(t.name.clone(), (t.role.clone(), up));
        }
        rounds += 1;
        let diag = diagnose(&round);
        if diag != last_diag {
            append(&dir, &serde_json::json!({"at": now(), "event": "diagnosis", "cause": diag}));
            last_diag = diag;
        }
        let per: serde_json::Map<String, serde_json::Value> = tally.iter().map(|(k, t)| {
            let n = t.ok + t.fail;
            let loss = if n == 0 { 0.0 } else { t.fail as f64 * 100.0 / n as f64 };
            (k.clone(), serde_json::json!({"up": t.up, "rtt_ms": t.last_ms, "loss_pct": loss}))
        }).collect();
        let _ = publish(&dir, "status.json", &serde_json::json!({"at": now(), "rounds": rounds, "cause": diag, "targets": per}));
        if rounds.is_multiple_of(summary) {
            append(&dir, &serde_json::json!({"at": now(), "event": "summary", "rounds": summary, "cause": diag, "targets": per}));
            for t in tally.values_mut() { t.ok = 0; t.fail = 0; }
        }
        let period = Duration::from_secs(every);
        if let Some(rest) = period.checked_sub(start.elapsed()) { std::thread::sleep(rest); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn r(v: &[(&str, &str, bool)]) -> BTreeMap<String, (String, bool)> { v.iter().map(|(n, ro, u)| (n.to_string(), (ro.to_string(), *u))).collect() }

    #[test]
    fn diagnosis_names_the_failing_link() {
        assert_eq!(diagnose(&r(&[("laptop", "peer", true), ("router", "lan", true), ("cf", "wan", true)])), "ok");
        assert_eq!(diagnose(&r(&[("laptop", "peer", false), ("router", "lan", true), ("cf", "wan", true)])), "peer");
        assert_eq!(diagnose(&r(&[("laptop", "peer", false), ("router", "lan", true), ("cf", "wan", false)])), "wan");
        assert_eq!(diagnose(&r(&[("laptop", "peer", false), ("router", "lan", false), ("cf", "wan", false)])), "lan");
    }

    #[test]
    fn parse_rejects_bad_targets() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(parse(&a(&["--dir", "x", "--target", "bogus:a=1.1.1.1:443"])).is_err());
        assert!(parse(&a(&["--dir", "x"])).is_err());
        let (_, every, _, _, t) = parse(&a(&["--dir", "x", "--every", "0", "--target", "wan:cf=1.1.1.1:443"])).unwrap();
        assert_eq!((every, t.len()), (1, 1));
    }

    #[test]
    fn probe_reports_closed_port_as_down() {
        assert!(probe("127.0.0.1:1", Duration::from_millis(300)).is_none());
    }
}
