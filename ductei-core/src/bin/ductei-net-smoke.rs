//! Manual multi-node smoke test for the `net` transport (GAP 4).
//!
//! Modes (all plain std, no extra dependencies):
//!   listen <addr> <log> <rej>                     serve peers until killed
//!   send <addr> <log> <rej> <node> <key> <scope> <lamport>
//!                                                 local-first send of one envelope
//!   dump <log> <rej>                              print what a log holds
//!   raw <addr>                                    one good frame, then a malformed one
//!   scenarios <addr>                              run all scenarios, nodes as separate processes
//!
//! `listen` refuses wildcard addresses: bind the Tailscale IP, never 0.0.0.0.
//! The wire has no encryption or authentication of its own; on a tailnet the
//! WireGuard tunnel provides both. This test shows behaviour across a real
//! network interface, not transport security.

use ductei_core::transport::{send_local_first, serve_connection, DeliveryPath};
use ductei_core::{scoped, Channel, ChannelError, ScopePolicy};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SCOPE_OK: &str = "qallow.semantic.cert";
const USAGE: &str = "usage: ductei-net-smoke listen <addr> <log> <rej> | send <addr> <log> <rej> <node> <key> <scope> <lamport> | dump <log> <rej> | raw <addr> | scenarios <addr>";

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(2)
}

fn node(n: u8) -> [u8; 16] {
    [n; 16]
}

fn open(log: &str, rej: &str) -> Channel {
    Channel::open(ScopePolicy::new().allow(SCOPE_OK), log, rej)
        .unwrap_or_else(|e| die(&format!("open {log}: {e}")))
}

fn write_frame(w: &mut impl Write, body: &[u8]) -> std::io::Result<()> {
    w.write_all(&(body.len() as u32).to_le_bytes())?;
    w.write_all(body)?;
    w.flush()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["listen", addr, log, rej] => listen(addr, log, rej),
        ["send", addr, log, rej, n, key, scope, lam] => send(addr, log, rej, n, key, scope, lam),
        ["dump", log, rej] => dump(log, rej),
        ["raw", addr] => raw(addr),
        ["scenarios", addr] => scenarios(addr),
        _ => die(USAGE),
    }
}

fn listen(addr: &str, log: &str, rej: &str) {
    if addr.starts_with("0.0.0.0") || addr.starts_with("[::]") {
        die("refusing to bind a wildcard address; use the Tailscale IP");
    }
    let mut ch = open(log, rej);
    let l = TcpListener::bind(addr).unwrap_or_else(|e| die(&format!("bind {addr}: {e}")));
    println!("LISTENING {}", l.local_addr().unwrap());
    let _ = std::io::stdout().flush();
    for conn in l.incoming() {
        match conn {
            Ok(s) => {
                let peer = s.peer_addr().map(|p| p.to_string()).unwrap_or_default();
                match serve_connection(s, &mut ch) {
                    Ok(n) => println!("CONN {peer} accepted={n}"),
                    Err(e) => println!("CONN {peer} ended with error: {e}"),
                }
                let _ = std::io::stdout().flush();
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
}

fn send(addr: &str, log: &str, rej: &str, n: &str, key: &str, scope: &str, lam: &str) {
    let mut local = open(log, rej);
    let node_id: u8 = n.parse().unwrap_or_else(|_| die("node must be 0-255"));
    let lamport: u64 = lam.parse().unwrap_or_else(|_| die("lamport must be a number"));
    let env = scoped(key, &[scope], node(node_id), lamport, b"x");
    match send_local_first(addr, &env, &mut local, ductei_core::transport::default_outbox_path()) {
        Ok(DeliveryPath::Network) => println!("DELIVERY Network"),
        Ok(DeliveryPath::LocalFallback) => println!("DELIVERY LocalFallback"),
        Err(ChannelError::ScopeDenied(k)) => {
            println!("DENIED {k}");
            std::process::exit(3)
        }
        Err(e) => {
            println!("ERROR {e:?}");
            std::process::exit(4)
        }
    }
}

fn dump(log: &str, rej: &str) {
    let ch = open(log, rej);
    let (envs, _) = ch.replay(0).unwrap_or_else(|e| die(&format!("replay: {e}")));
    let keys: Vec<&str> = envs.iter().map(|e| e.key.as_str()).collect();
    println!("COUNT {} KEYS {}", envs.len(), keys.join(","));
}

fn raw(addr: &str) {
    let mut s = TcpStream::connect(addr).unwrap_or_else(|e| die(&format!("connect {addr}: {e}")));
    let env = scoped("d", &[SCOPE_OK], node(1), 4, b"x");
    write_frame(&mut s, &serde_json::to_vec(&env).unwrap()).unwrap();
    let mut ack = [0u8; 1];
    s.read_exact(&mut ack).unwrap();
    println!("RAWACK {}", ack[0]);
    // Valid length prefix, body that is not JSON.
    write_frame(&mut s, &[0, 1, 2, 3, 4]).unwrap();
}

// ---- scenario runner: every node is its own process ----

fn exe() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|e| die(&format!("current_exe: {e}")))
}

fn run(args: &[&str]) -> (String, i32) {
    let o = Command::new(exe())
        .args(args)
        .output()
        .unwrap_or_else(|e| die(&format!("spawn: {e}")));
    (
        String::from_utf8_lossy(&o.stdout).trim().to_string(),
        o.status.code().unwrap_or(-1),
    )
}

fn start_listener(addr: &str, log: &str, rej: &str, out: &Path) -> Child {
    let f = std::fs::File::create(out).unwrap_or_else(|e| die(&format!("create {}: {e}", out.display())));
    let child = Command::new(exe())
        .args(["listen", addr, log, rej])
        .stdout(Stdio::from(f))
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| die(&format!("spawn listener: {e}")));
    let t = Instant::now();
    while TcpStream::connect(addr).is_err() {
        if t.elapsed() > Duration::from_secs(10) {
            die("listener did not come up within 10 seconds");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    child
}

fn stop_listener(mut c: Child, out: &Path) {
    let _ = c.kill();
    let _ = c.wait();
    if let Ok(t) = std::fs::read_to_string(out) {
        for l in t.lines() {
            println!("   listener: {l}");
        }
    }
}

fn check(fails: &mut u32, name: &str, ok: bool) {
    println!("{} {name}", if ok { "PASS" } else { "FAIL" });
    if !ok {
        *fails += 1;
    }
}

fn scenarios(addr: &str) {
    let dir = std::env::temp_dir().join(format!("ductei-net-smoke-{}", std::process::id()));
    // A reused pid must not inherit an earlier run's channel files (they would read as stale).
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| die(&format!("mkdir: {e}")));
    let p = |n: &str| dir.join(n).to_string_lossy().into_owned();
    let (rl, rr) = (p("remote.jsonl"), p("remote-rej.jsonl"));
    let (ll, lr) = (p("local.jsonl"), p("local-rej.jsonl"));
    let mut f = 0u32;
    println!("ductei-net-smoke scenarios against {addr}");
    println!("work dir {}", dir.display());

    println!("\n== S1 good session, S2 scope denial and stale receipt");
    let out1 = dir.join("listener-1.txt");
    let l = start_listener(addr, &rl, &rr, &out1);
    let (o, c) = run(&["send", addr, &ll, &lr, "1", "a", SCOPE_OK, "1"]);
    check(&mut f, "good envelope delivered over the network", c == 0 && o == "DELIVERY Network");
    let (o, c) = run(&["send", addr, &ll, &lr, "1", "b", "limen.credentials", "2"]);
    check(&mut f, "out-of-scope envelope denied by the peer", c == 3 && o.starts_with("DENIED"));
    // A stale/duplicate delta is acked 2, a successful receipt (see the ack tri-state in
    // transport.rs), not a denial. The dump below proves it was not applied a second time.
    let (o, c) = run(&["send", addr, &ll, &lr, "1", "a", SCOPE_OK, "1"]);
    check(&mut f, "already-held envelope receipted by the peer, not denied", c == 0 && o == "DELIVERY Network");
    stop_listener(l, &out1);
    let (o, _) = run(&["dump", &rl, &rr]);
    check(&mut f, "remote log holds exactly the one accepted envelope", o == "COUNT 1 KEYS a");
    let (o, _) = run(&["dump", &ll, &lr]);
    check(&mut f, "denied sends did not fall back to the local log", o == "COUNT 0 KEYS");

    println!("\n== S3 restart replay (listener process killed and restarted)");
    let out2 = dir.join("listener-2.txt");
    let l = start_listener(addr, &rl, &rr, &out2);
    let (o, c) = run(&["send", addr, &ll, &lr, "1", "c", SCOPE_OK, "3"]);
    check(&mut f, "new envelope accepted after restart", c == 0 && o == "DELIVERY Network");
    let (o, c) = run(&["send", addr, &ll, &lr, "1", "a", SCOPE_OK, "1"]);
    check(&mut f, "pre-restart envelope still receipted as already held (gate rebuilt from log)", c == 0 && o == "DELIVERY Network");
    stop_listener(l, &out2);
    let (o, _) = run(&["dump", &rl, &rr]);
    check(&mut f, "log holds a and c, nothing lost or duplicated", o == "COUNT 2 KEYS a,c");

    println!("\n== S4 malformed frame");
    let out3 = dir.join("listener-3.txt");
    let l = start_listener(addr, &rl, &rr, &out3);
    let (o, _) = run(&["raw", addr]);
    check(&mut f, "valid frame before the bad one was acked", o == "RAWACK 1");
    let (o, c) = run(&["send", addr, &ll, &lr, "1", "e", SCOPE_OK, "5"]);
    check(&mut f, "listener survived the malformed frame and still accepts", c == 0 && o == "DELIVERY Network");
    stop_listener(l, &out3);
    let (o, _) = run(&["dump", &rl, &rr]);
    check(&mut f, "log holds a,c,d,e and the bad frame never touched it", o == "COUNT 4 KEYS a,c,d,e");

    println!("\n== S5 unreachable peer (no listener)");
    let (o, c) = run(&["send", addr, &ll, &lr, "1", "f", SCOPE_OK, "6"]);
    check(&mut f, "send degraded to the local channel", c == 0 && o == "DELIVERY LocalFallback");
    let (o, _) = run(&["dump", &ll, &lr]);
    check(&mut f, "local log holds the envelope", o == "COUNT 1 KEYS f");
    let (o, _) = run(&["dump", &rl, &rr]);
    check(&mut f, "remote log unchanged", o == "COUNT 4 KEYS a,c,d,e");

    println!("\n{} failed", f);
    std::process::exit(if f == 0 { 0 } else { 1 });
}
