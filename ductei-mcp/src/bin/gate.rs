//! ductei-mcp-gate: stdio MCP gateway.
//!
//!   ductei-mcp-gate run <config.toml>
//!       relay client<->server with scope + persistence + receipts
//!   ductei-mcp-gate verify <ductei_dir> [--pubkey <file> | --fingerprint <hex> | --allow-unpinned]
//!       recompute the receipt chain, signatures, key pin and log cross-checks
//!   ductei-mcp-gate fingerprint <ductei_dir>
//!       print the SHA-256 of the public key in the log dir (pin this somewhere else)
//!
//! Point your MCP client at this binary instead of the real server; the gate
//! spawns the real server from [server] in the config. MCP stdio framing is
//! newline-delimited JSON-RPC, so the relay is line based. The gate's own
//! diagnostics go to stderr (stdout is the protocol channel).
use ductei_mcp::{anchors_in, new_launch, push_envelope, sha256_hex, verify_receipts, Config, Decision, Gate, Signer, VerifyTrust, GATE_NONCE_ENV};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

const USAGE: &str = "usage: ductei-mcp-gate run <config.toml>\n       ductei-mcp-gate verify <ductei_dir> [--pubkey <file> | --fingerprint <hex> | --allow-unpinned] [--anchor <seq>:<hash>] [--anchor-file <peer channel.jsonl>]\n       ductei-mcp-gate fingerprint <ductei_dir>";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(String::as_str) {
        Some("run") if args.len() == 3 => run(Path::new(&args[2])),
        Some("verify") if args.len() >= 3 => verify(Path::new(&args[2]), &args[3..]),
        Some("fingerprint") if args.len() == 3 => fingerprint(Path::new(&args[2])),
        _ => { eprintln!("{USAGE}"); 2 }
    };
    std::process::exit(code);
}

fn fingerprint(dir: &Path) -> i32 {
    match Signer::load_public(dir) {
        Ok(Some((scheme, pk))) => { println!("{} {}", scheme.as_str(), sha256_hex(&pk)); 0 }
        Ok(None) => { eprintln!("no public key in {}", dir.display()); 1 }
        Err(e) => { eprintln!("error: {e}"); 2 }
    }
}

fn verify(dir: &Path, flags: &[String]) -> i32 {
    let mut trust = VerifyTrust::default();
    let mut i = 0;
    while i < flags.len() {
        match flags[i].as_str() {
            "--pubkey" if i + 1 < flags.len() => {
                match std::fs::read(&flags[i + 1]) { Ok(b) => trust.pubkey = Some(b), Err(e) => { eprintln!("--pubkey {}: {e}", flags[i + 1]); return 2; } }
                i += 2;
            }
            "--fingerprint" if i + 1 < flags.len() => { trust.fingerprint = Some(flags[i + 1].clone()); i += 2; }
            "--allow-unpinned" => { trust.allow_unpinned = true; i += 1; }
            "--anchor" if i + 1 < flags.len() => {
                let Some((seq, head)) = flags[i + 1].split_once(':') else { eprintln!("--anchor wants <seq>:<hash>"); return 2; };
                let Ok(seq) = seq.parse::<u64>() else { eprintln!("--anchor: bad seq"); return 2; };
                trust.pinned_head = Some((seq, head.to_string()));
                i += 2;
            }
            "--anchor-file" if i + 1 < flags.len() => {
                match anchors_in(Path::new(&flags[i + 1])) { Ok(a) => trust.anchors.extend(a), Err(e) => { eprintln!("--anchor-file: {e}"); return 2; } }
                i += 2;
            }
            _ => { eprintln!("{USAGE}"); return 2; }
        }
    }
    match verify_receipts(dir, &trust) {
        Ok(rep) => {
            for w in &rep.warnings { eprintln!("note: {w}"); }
            if let Some(k) = &rep.kid { eprintln!("key: {k}"); }
            if rep.ok() { eprintln!("ok: {} receipts, chain intact", rep.receipts); 0 }
            else { eprintln!("FAIL: {} receipts, {} problems", rep.receipts, rep.errors.len()); for e in rep.errors { eprintln!("  {e}"); } 1 }
        }
        Err(e) => { eprintln!("error: {e}"); 2 }
    }
}

fn run(config_path: &Path) -> i32 {
    let cfg = match Config::load(config_path) { Ok(c) => c, Err(e) => { eprintln!("ductei-mcp-gate: {e}"); return 2; } };
    let dir = cfg.log_dir(config_path);
    let gate = match Gate::open(&cfg, &dir) { Ok(g) => g, Err(e) => { eprintln!("ductei-mcp-gate: {e}"); return 2; } };
    eprintln!("ductei-mcp-gate: server={} allow={:?} dir={}", cfg.server.name, cfg.policy.allow, dir.display());
    if gate.receipts.signer.created {
        eprintln!("ductei-mcp-gate: NEW signing key {} fingerprint {}", gate.receipts.signer.scheme.as_str(), gate.receipts.signer.kid);
        eprintln!("ductei-mcp-gate: copy that fingerprint somewhere this machine cannot edit, and set sign.pubkey_fingerprint in the config");
    } else if !gate.receipts.signer.kid.is_empty() {
        eprintln!("ductei-mcp-gate: signing key {}{}", gate.receipts.signer.kid, if cfg.sign.pubkey_fingerprint.is_some() { " (pinned)" } else { " (NOT pinned)" });
    }

    // Launch nonce: the child can prove it was started by this gate.
    let (nonce, _launch) = match new_launch(&dir, &cfg.server.name, gate.node) {
        Ok(x) => x,
        Err(e) => { eprintln!("ductei-mcp-gate: launch record: {e}"); return 2; }
    };

    // Anchor pusher: one thread, never blocks the relay. Only the newest
    // unsent anchor is kept; an older one is superseded by construction.
    let mut gate = gate;
    let anchor_rx = if cfg.anchor.every > 0 && !cfg.anchor.peers.is_empty() {
        let (tx, rx) = mpsc::channel();
        gate.anchor_tx = Some(tx);
        Some(rx)
    } else { None };
    let anchor_thread = anchor_rx.map(|rx| {
        let peers = cfg.anchor.peers.clone();
        let timeout = Duration::from_millis(cfg.anchor.connect_timeout_ms);
        let outbox = dir.join("outbox.jsonl");
        thread::spawn(move || {
            let mut pending = None;
            let mut sent = 0u64;
            let mut failed = 0u64;
            for env in rx {
                let mut ok_any = false;
                for p in &peers {
                    match push_envelope(p, &env, timeout, &outbox) {
                        Ok(1) | Ok(2) => ok_any = true,
                        Ok(code) => eprintln!("ductei-mcp-gate: anchor rejected by {p} (ack {code}); does its policy allow the anchor scope?"),
                        Err(e) => eprintln!("ductei-mcp-gate: anchor push failed: {e}"),
                    }
                }
                // Newest anchor always wins; an unsent older one is superseded.
                pending = if ok_any { sent += 1; None } else { failed += 1; Some(env) };
            }
            // Channel closed: last chance for whatever is still unsent.
            if let Some(env) = pending {
                for p in &peers { if matches!(push_envelope(p, &env, timeout, &outbox), Ok(1) | Ok(2)) { sent += 1; failed = failed.saturating_sub(1); break; } }
            }
            eprintln!("ductei-mcp-gate: anchors pushed={sent} unsent={failed}");
        })
    });

    let mut child = match Command::new(&cfg.server.command)
        .args(&cfg.server.args)
        .env(GATE_NONCE_ENV, &nonce)
        .env("DUCTEI_GATE_DIR", &dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => { eprintln!("ductei-mcp-gate: spawn {}: {e}", cfg.server.command); return 2; }
    };
    let mut child_in = child.stdin.take().expect("piped stdin");
    let child_out = child.stdout.take().expect("piped stdout");

    let gate = Arc::new(Mutex::new(gate));
    let client_out = Arc::new(Mutex::new(std::io::stdout()));

    // client -> gate -> server
    let g1 = Arc::clone(&gate);
    let o1 = Arc::clone(&client_out);
    let to_server = thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() { continue; }
            let decision = g1.lock().unwrap().on_client_line(&line);
            match decision {
                Decision::Forward => {
                    if writeln!(child_in, "{line}").and_then(|_| child_in.flush()).is_err() { break; }
                }
                Decision::Reply(reply) => {
                    let mut o = o1.lock().unwrap();
                    let _ = writeln!(o, "{reply}").and_then(|_| o.flush());
                }
            }
        }
        // client went away: closing child stdin tells the server to exit
    });

    // server -> gate -> client
    let g2 = Arc::clone(&gate);
    let o2 = Arc::clone(&client_out);
    let to_client = thread::spawn(move || {
        for line in BufReader::new(child_out).lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() { continue; }
            let out = match g2.lock().unwrap().on_server_line(&line) {
                Ok(Some(rewritten)) => rewritten,
                Ok(None) => line,
                Err(e) => {
                    // persistence-before-ack: a result we could not persist is not returned
                    eprintln!("ductei-mcp-gate: dropping result, persist failed: {e:?}");
                    continue;
                }
            };
            let mut o = o2.lock().unwrap();
            if writeln!(o, "{out}").and_then(|_| o.flush()).is_err() { break; }
        }
    });

    let _ = to_client.join();
    let _ = to_server.join();
    let status = child.wait().map(|s| s.code().unwrap_or(1)).unwrap_or(1);
    {
        let mut g = gate.lock().unwrap();
        // Anchor the final head on exit even if it is not on an `every` boundary,
        // then close the channel so the pusher drains and stops.
        if cfg.anchor.every > 0 {
            if let Some(env) = g.anchor_now() {
                let _ = g.anchors.append(&env);
                if let Some(tx) = &g.anchor_tx { let _ = tx.send(env); }
            }
        }
        g.anchor_tx = None;
        eprintln!("ductei-mcp-gate: exit, calls={} receipts={} head={}", g.calls, g.receipts.seq, &g.receipts.head[..16]);
    }
    if let Some(t) = anchor_thread { let _ = t.join(); }
    let _ = std::fs::remove_file(dir.join(ductei_mcp::GATE_LAUNCH_FILE));
    status
}
