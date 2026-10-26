//! ductei-node: heartbeat loop (ATRIUM harness-roadmap/05-heartbeat-loop.md).
//!
//!   ductei-node run       <flags>   listen, send heartbeats, watch peers
//!   ductei-node supervise <flags>   keep one `run` child alive, bounded
//!
//! Flags: --name N --id 0-255 --listen ADDR --peer NAME=ADDR (repeatable)
//!        --dir DIR [--beat-secs 30] [--suspect-secs 90] [--unreachable-secs 300]
//!
//! Peers only observe and report. A node restarts only itself, through its
//! own supervisor, at most 3 times per hour, then stops and writes a
//! plain-English record to <dir>/failed/. Nothing is deleted.
//! The wire has no encryption or authentication of its own; bind the
//! Tailscale address, never a wildcard.

use ductei_core::transport::{send_local_first, serve_connection, DeliveryPath};
use ductei_core::{scoped, Channel, ChannelError, ScopePolicy};
use std::collections::HashMap;
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SCOPE_HB: &str = "ductei.heartbeat";
const MAX_RESTARTS_PER_HOUR: usize = 3;
const USAGE: &str = "usage: ductei-node run|supervise --name N --id ID --listen ADDR --peer NAME=ADDR --dir DIR [--beat-secs S --suspect-secs S --unreachable-secs S] [--allow-scope SCOPE]...";

#[derive(Clone)]
struct Cfg {
    name: String,
    id: u8,
    listen: String,
    peers: Vec<(String, String)>,
    dir: PathBuf,
    beat: u64,
    suspect: u64,
    unreachable: u64,
    html: Option<PathBuf>,
    allow: Vec<String>,
}

type Seen = Arc<Mutex<HashMap<String, (Instant, u64)>>>;

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(2)
}

fn node(n: u8) -> [u8; 16] {
    [n; 16]
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn hms(t: u64) -> String {
    format!("{:02}:{:02}:{:02}Z", (t / 3600) % 24, (t / 60) % 60, t % 60)
}

fn witness(dir: &Path, name: &str, msg: &str) {
    let line = format!("{} [{}] {}", hms(now_secs()), name, msg);
    println!("{line}");
    let _ = std::io::stdout().flush();
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("witness.log")) {
        let _ = writeln!(f, "{line}");
    }
}

fn parse(args: &[String]) -> Cfg {
    let mut c = Cfg {
        name: String::new(),
        id: 0,
        listen: String::new(),
        peers: vec![],
        dir: PathBuf::new(),
        beat: 30,
        suspect: 90,
        unreachable: 300,
        html: None,
        allow: vec![],
    };
    let mut i = 0;
    while i < args.len() {
        let v = || -> String {
            args.get(i + 1).cloned().unwrap_or_else(|| die(&format!("{} needs a value", args[i])))
        };
        let num = |s: String| -> u64 { s.parse().unwrap_or_else(|_| die("expected a whole number of seconds")) };
        match args[i].as_str() {
            "--name" => c.name = v(),
            "--id" => c.id = v().parse().unwrap_or_else(|_| die("--id must be 0-255")),
            "--listen" => c.listen = v(),
            "--peer" => {
                let s = v();
                let (n, a) = s.split_once('=').unwrap_or_else(|| die("--peer needs NAME=ADDR"));
                c.peers.push((n.to_string(), a.to_string()));
            }
            "--dir" => c.dir = PathBuf::from(v()),
            "--beat-secs" => c.beat = num(v()),
            "--suspect-secs" => c.suspect = num(v()),
            "--unreachable-secs" => c.unreachable = num(v()),
            "--html" => c.html = Some(PathBuf::from(v())),
            "--allow-scope" => c.allow.push(v()),
            other => die(&format!("unknown flag {other}\n{USAGE}")),
        }
        i += 2;
    }
    if c.name.is_empty() || c.listen.is_empty() || c.dir.as_os_str().is_empty() {
        die(USAGE);
    }
    c
}

fn read_counter(p: &Path) -> u64 {
    std::fs::read_to_string(p).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

fn write_counter(p: &Path, n: u64) {
    if let Ok(mut f) = std::fs::File::create(p) {
        let _ = write!(f, "{n}");
        let _ = f.sync_all();
    }
}

fn read_history(p: &Path) -> Vec<u64> {
    let now = now_secs();
    std::fs::read_to_string(p)
        .map(|s| s.lines().filter_map(|l| l.trim().parse::<u64>().ok()).filter(|t| now.saturating_sub(*t) < 3600).collect())
        .unwrap_or_default()
}

fn write_history(p: &Path, v: &[u64]) {
    let body: Vec<String> = v.iter().map(|t| t.to_string()).collect();
    if let Ok(mut f) = std::fs::File::create(p) {
        let _ = writeln!(f, "{}", body.join("\n"));
        let _ = f.sync_all();
    }
}

fn render_html(name: &str, updated: u64, rows: &[(String, &'static str, u64, String)]) -> String {
    let mut body = String::new();
    for (peer, st, age, ctr) in rows {
        let color = match *st {
            "HEALTHY" => "#3fb950",
            "SUSPECT" => "#d29922",
            _ => "#f85149",
        };
        body.push_str(&format!(
            "<tr><td>{peer}</td><td style=\"color:{color}\"><b>{st}</b></td><td>{age} s</td><td>{ctr}</td></tr>"
        ));
    }
    format!(
        "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><meta http-equiv=refresh content=15><meta name=robots content=noindex><title>nodes</title><style>body{{font-family:system-ui;background:#0e1116;color:#e6e6e6;margin:0;padding:1.2em;max-width:820px}}table{{width:100%;border-collapse:collapse}}td,th{{text-align:left;padding:.4em .6em;border-bottom:1px solid #30363d}}small{{color:#8b949e}}</style></head><body><h1>ductei nodes</h1><p><small>Seen from {name}. Updated {} (UTC). Peers only observe and report; each node restarts only itself.</small></p><table><tr><th>peer</th><th>state</th><th>last heartbeat</th><th>last counter</th></tr>{body}</table></body></html>",
        hms(updated)
    )
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => run(parse(&args[1..])),
        Some("supervise") => supervise(&args[1..]),
        _ => die(USAGE),
    }
}

fn run(c: Cfg) {
    if c.listen.starts_with("0.0.0.0") || c.listen.starts_with("[::]") {
        die("refusing to bind a wildcard address; use the Tailscale IP");
    }
    std::fs::create_dir_all(&c.dir).unwrap_or_else(|e| die(&format!("mkdir {}: {e}", c.dir.display())));
    let policy = || c.allow.iter().fold(ScopePolicy::new().allow(SCOPE_HB), |p, s| p.allow(s));
    let open = |log: &str, rej: &str| -> Channel {
        Channel::open(policy(), c.dir.join(log), c.dir.join(rej)).unwrap_or_else(|e| die(&format!("open {log}: {e}")))
    };
    let mut inbox = open("inbox.jsonl", "inbox-rej.jsonl");
    let mut spool = open("spool.jsonl", "spool-rej.jsonl");

    // The counter is daemon-owned: resume above everything ever sent, never reset.
    let own_key = format!("hb.{}", c.name);
    let spool_max = spool
        .replay(0)
        .map(|(e, _)| e.iter().filter(|x| x.key == own_key).map(|x| x.lamport).max().unwrap_or(0))
        .unwrap_or(0);
    let counter_path = c.dir.join("lamport");
    let mut lamport = read_counter(&counter_path).max(spool_max);
    witness(
        &c.dir,
        &c.name,
        &format!("node {} starting on {}, heartbeat counter resumes after {}", c.name, c.listen, lamport),
    );

    let started = Instant::now();
    let seen: Seen = Arc::new(Mutex::new(HashMap::new()));

    // Listener: every inbound beat passes scope, gate and fsynced log before the ack.
    let listener = TcpListener::bind(&c.listen).unwrap_or_else(|e| die(&format!("bind {}: {e}", c.listen)));
    {
        let seen = seen.clone();
        let c = c.clone();
        std::thread::spawn(move || {
            let mut cursor = inbox.replay(0).map(|x| x.1).unwrap_or(0);
            for conn in listener.incoming() {
                let Ok(s) = conn else { continue };
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                if let Err(e) = serve_connection(s, &mut inbox) {
                    witness(&c.dir, &c.name, &format!("a peer connection ended with an error and was dropped: {e}"));
                }
                if let Ok((envs, cur)) = inbox.replay(cursor) {
                    cursor = cur;
                    for e in envs {
                        if let Some(p) = e.key.strip_prefix("hb.") {
                            seen.lock().unwrap().insert(p.to_string(), (Instant::now(), e.lamport));
                        }
                    }
                }
            }
        });
    }

    // Monitor: plain-English state changes, thresholds fixed before the trial.
    {
        let seen = seen.clone();
        let c = c.clone();
        std::thread::spawn(move || {
            let mut prev: HashMap<String, &'static str> = HashMap::new();
            loop {
                let mut status = format!("node={} updated={}\n", c.name, now_secs());
                let mut rows: Vec<(String, &'static str, u64, String)> = Vec::new();
                for (peer, _) in &c.peers {
                    let (age, lam) = {
                        let g = seen.lock().unwrap();
                        match g.get(peer) {
                            Some((t, l)) => (t.elapsed().as_secs(), Some(*l)),
                            None => (started.elapsed().as_secs(), None),
                        }
                    };
                    let st = if age <= c.suspect {
                        "HEALTHY"
                    } else if age <= c.unreachable {
                        "SUSPECT"
                    } else {
                        "UNREACHABLE"
                    };
                    status.push_str(&format!(
                        "peer={peer} state={st} age_secs={age} last_counter={}\n",
                        lam.map(|l| l.to_string()).unwrap_or_else(|| "none".into())
                    ));
                    rows.push((peer.clone(), st, age, lam.map(|l| l.to_string()).unwrap_or_else(|| "none".into())));
                    let old = prev.insert(peer.clone(), st);
                    if old == Some(st) || (old.is_none() && lam.is_none() && st == "HEALTHY") {
                        continue;
                    }
                    let msg = match st {
                        "HEALTHY" if old.is_none() => format!("peer {peer}: first heartbeat received (counter {})", lam.unwrap_or(0)),
                        "HEALTHY" => format!("peer {peer} is HEALTHY again: heartbeat received (counter {})", lam.unwrap_or(0)),
                        "SUSPECT" => format!(
                            "peer {peer} is SUSPECT: no heartbeat for {age} s (threshold {} s). Observing only; this node never restarts a peer.",
                            c.suspect
                        ),
                        _ => format!(
                            "peer {peer} is UNREACHABLE: no heartbeat for {age} s (threshold {} s). Reported as unreachable, not failed: the peer may be asleep or offline.",
                            c.unreachable
                        ),
                    };
                    witness(&c.dir, &c.name, &msg);
                }
                let _ = std::fs::write(c.dir.join("status.txt"), status);
                if let Some(h) = &c.html {
                    let tmp = h.with_extension("tmp");
                    let page = render_html(&c.name, now_secs(), &rows);
                    let swapped = std::fs::write(&tmp, &page).is_ok() && std::fs::rename(&tmp, h).is_ok();
                    if !swapped {
                        // Windows can refuse to replace a file another program has open; the page is tiny, so write it in place.
                        let _ = std::fs::write(h, &page);
                        let _ = std::fs::remove_file(&tmp);
                    }
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });
    }

    // Beats: one bounded send per peer per tick, local-first, best effort.
    let mut last_path: HashMap<String, &'static str> = HashMap::new();
    loop {
        lamport += 1;
        write_counter(&counter_path, lamport);
        let payload = format!("uptime_secs={};build=1", started.elapsed().as_secs());
        let env = scoped(&own_key, &[SCOPE_HB], node(c.id), lamport, payload.as_bytes());
        for (peer, addr) in &c.peers {
            let res = send_local_first(addr.as_str(), &env, &mut spool, ductei_core::transport::default_outbox_path());
            let path = match &res {
                Ok(DeliveryPath::Network) => "delivered",
                Ok(DeliveryPath::LocalFallback) => "spooled",
                Err(ChannelError::ScopeDenied(_)) => "denied",
                Err(_) => "error",
            };
            if last_path.insert(peer.clone(), path) != Some(path) {
                let msg = match path {
                    "delivered" => format!("heartbeat to peer {peer} delivered (counter {lamport})"),
                    "spooled" => format!("peer {peer} not reachable: heartbeats are being spooled locally (counter {lamport})"),
                    "denied" => format!("peer {peer} denied heartbeat {lamport} (stale counter or out of scope)"),
                    _ => format!("heartbeat to peer {peer} failed with a local error: {res:?}"),
                };
                witness(&c.dir, &c.name, &msg);
            }
        }
        std::thread::sleep(Duration::from_secs(c.beat));
    }
}

fn supervise(args: &[String]) {
    let c = parse(args);
    let _ = std::fs::create_dir_all(c.dir.join("failed"));
    let hist = c.dir.join("restarts.txt");
    let mut restarts: Vec<u64> = read_history(&hist);
    loop {
        let exe = std::env::current_exe().unwrap_or_else(|e| die(&format!("current_exe: {e}")));
        let mut child = Command::new(exe)
            .arg("run")
            .args(args)
            .stdin(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| die(&format!("spawn node: {e}")));
        witness(&c.dir, &c.name, &format!("supervisor started node process {}", child.id()));
        let status = child.wait().map(|s| s.to_string()).unwrap_or_else(|e| format!("wait error: {e}"));
        witness(&c.dir, &c.name, &format!("node process exited ({status})"));
        restarts.retain(|t| now_secs().saturating_sub(*t) < 3600);
        if restarts.len() >= MAX_RESTARTS_PER_HOUR {
            let f = c.dir.join("failed").join(format!("{}-restart-limit.txt", now_secs()));
            let msg = format!(
                "Node {} was stopped by its supervisor at {} (UTC).\nIt exited {} times within one hour; the limit is {} restarts per hour.\nLast exit status: {}.\nThe supervisor will not retry. Nothing was deleted: logs are in {}.\nThe restart history is kept in restarts.txt and clears an hour after its oldest entry.\nTo start again, run the supervise command by hand.\n",
                c.name,
                hms(now_secs()),
                restarts.len() + 1,
                MAX_RESTARTS_PER_HOUR,
                status,
                c.dir.display()
            );
            let _ = std::fs::write(&f, msg);
            witness(&c.dir, &c.name, &format!("restart limit reached; wrote {}", f.display()));
            std::process::exit(1);
        }
        restarts.push(now_secs());
        write_history(&hist, &restarts);
        std::thread::sleep(Duration::from_secs(1));
        witness(
            &c.dir,
            &c.name,
            &format!("restarting node (restart {} of {} allowed this hour)", restarts.len(), MAX_RESTARTS_PER_HOUR),
        );
    }
}
