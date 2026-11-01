// Copyright (C) 2026 xingxerx
// Licensed under the Apache License 2.0. See the LICENSE file in the repository root.

//! atrium: the one front door.
//!
//!   atrium up     <atrium.toml>   boot and watch every room until `atrium down` or Ctrl+C
//!   atrium status <atrium.toml>   print the live status (exit 0 all up, 2 something down, 3 no supervisor)
//!   atrium verify <atrium.toml>   run every verify step, chain the outcomes, verify the chain (exit 0/1)
//!   atrium down   <atrium.toml>   ask the running supervisor to stop its managed rooms and exit

use atrium_ctl::{slog, Config, Health, Status, Supervisor};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

fn usage() -> ! {
    eprintln!("usage: atrium up|status|verify|down <atrium.toml>");
    std::process::exit(64);
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 { usage(); }
    let cfg = match Config::load(Path::new(&a[2])) { Ok(c) => c, Err(e) => { eprintln!("atrium: {e}"); std::process::exit(65); } };
    let code = match a[1].as_str() {
        "up" => up(cfg),
        "status" => status(&cfg),
        "verify" => verify(cfg),
        "down" => down(&cfg),
        _ => usage(),
    };
    std::process::exit(code);
}

fn stop_file(state: &Path) -> std::path::PathBuf { state.join("stop") }

fn up(cfg: Config) -> i32 {
    // One supervisor per state dir.
    if let Ok(s) = Status::load(&cfg.state) {
        if s.live(Duration::from_secs(10)) {
            eprintln!("atrium: a supervisor (pid {}) is already running on {}", s.supervisor_pid, cfg.state.display());
            return 75;
        }
    }
    let _ = fs::remove_file(stop_file(&cfg.state));
    let tick = Duration::from_millis(cfg.tick_ms);
    let state = cfg.state.clone();
    let mut sup = match Supervisor::open(cfg) { Ok(s) => s, Err(e) => { eprintln!("atrium: {e}"); return 70; } };
    slog(&state, &format!("up: pid {} chain seq {} head {}", std::process::id(), sup.status().chain_seq, &sup.status().chain_head[..12]));
    let mut last_all_up: Option<bool> = None;
    loop {
        let t0 = Instant::now();
        match sup.tick() {
            Ok(_) => {
                let now_up = sup.status().all_up();
                if last_all_up != Some(now_up) {
                    let down: Vec<&str> = sup.status().rooms.iter().filter(|(_, r)| r.health != Health::Up).map(|(n, _)| n.as_str()).collect();
                    slog(&state, &if now_up { "all rooms up".to_string() } else { format!("not all up: {}", down.join(", ")) });
                    last_all_up = Some(now_up);
                }
            }
            Err(e) => { slog(&state, &format!("tick failed, stopping (chain must not drift): {e}")); let _ = sup.shutdown(); return 74; }
        }
        if stop_file(&state).exists() {
            slog(&state, "down requested");
            let _ = fs::remove_file(stop_file(&state));
            let _ = sup.shutdown();
            return 0;
        }
        // Real-time rule: a tick never overruns; sleep only the remainder.
        let spent = t0.elapsed();
        if spent < tick { std::thread::sleep(tick - spent); }
    }
}

fn status(cfg: &Config) -> i32 {
    let s = match Status::load(&cfg.state) { Ok(s) => s, Err(e) => { eprintln!("atrium: no status ({e})"); return 3; } };
    let live = s.live(Duration::from_secs(10));
    println!("supervisor pid {} {} | tick {} | chain seq {} head {}", s.supervisor_pid, if live { "live" } else { "STALE" }, s.tick, s.chain_seq, &s.chain_head[..12.min(s.chain_head.len())]);
    for (n, r) in &s.rooms {
        let h = match r.health { Health::Up => "up", Health::Down => "DOWN", Health::Blocked => "blocked" };
        println!("  {n:<16} {h:<8} pid {:<7} restarts {:<3} {}", r.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()), r.restarts, r.note);
    }
    if !live { 3 } else if s.all_up() { 0 } else { 2 }
}

fn verify(cfg: Config) -> i32 {
    // Verify runs in its own process but appends to the same chain. If a
    // supervisor is live, we still append; ReceiptLog is append-only and the
    // supervisor re-reads nothing, so the two writers would interleave seqs.
    // To keep one writer per chain, verify refuses while a supervisor is live
    // and the operator runs it through the supervisor's quiet window instead.
    if let Ok(s) = Status::load(&cfg.state) {
        if s.live(Duration::from_secs(10)) {
            eprintln!("atrium: supervisor pid {} is live; run `atrium down` first or verify against a copy (one writer per chain)", s.supervisor_pid);
            return 75;
        }
    }
    let state = cfg.state.clone();
    let mut sup = match Supervisor::open(cfg) { Ok(s) => s, Err(e) => { eprintln!("atrium: {e}"); return 70; } };
    let (pass, fail) = match sup.run_verify(|name, ok, detail| {
        println!("{} {name}: {detail}", if ok { "PASS" } else { "FAIL" });
        slog(&state, &format!("verify {name}: {} {detail}", if ok { "PASS" } else { "FAIL" }));
    }) { Ok(r) => r, Err(e) => { eprintln!("atrium: verify: {e}"); return 70; } };
    println!("verify: {pass} pass, {fail} fail");
    if fail == 0 { 0 } else { 1 }
}

fn down(cfg: &Config) -> i32 {
    let s = match Status::load(&cfg.state) { Ok(s) => s, Err(_) => { println!("atrium: no supervisor"); return 0; } };
    if !s.live(Duration::from_secs(10)) { println!("atrium: supervisor not live (last pid {})", s.supervisor_pid); return 0; }
    if let Err(e) = fs::write(stop_file(&cfg.state), b"stop") { eprintln!("atrium: {e}"); return 74; }
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        if !stop_file(&cfg.state).exists() { println!("atrium: stopped"); return 0; }
    }
    eprintln!("atrium: supervisor did not acknowledge in 15s");
    1
}
