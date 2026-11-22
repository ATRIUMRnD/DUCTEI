// Copyright (C) 2026 xingxerx
// Licensed under the Apache License 2.0. See the LICENSE file in the repository root.

//! atrium: the one front door.
//!
//!   atrium up     <atrium.toml>   boot and watch every room until `atrium down` or Ctrl+C
//!   atrium status <atrium.toml>   print the live status (exit 0 all up, 2 something down, 3 no supervisor)
//!   atrium verify <atrium.toml>   run every verify step, chain the outcomes, verify the chain (exit 0/1);
//!                                 with a live supervisor the request is queued to it, so rooms stay up
//!   atrium check  <atrium.toml>   read-only chain check against peer anchors; safe any time, any count (exit 0/1)
//!   atrium down   <atrium.toml>   ask the running supervisor to stop its managed rooms and exit
//!   atrium watchdog <atrium.toml> one pass: start the atrium task if the supervisor died
//!                                 without `atrium down` (max 3 an hour, one phone line each)

use atrium_ctl::{is_device_lost, now_unix, slog, Config, Health, Status, Supervisor};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

/// How often a held supervisor probes for its drive.
const DRIVE_PROBE: Duration = Duration::from_secs(5);

fn usage() -> ! {
    eprintln!("usage: atrium up|status|verify|check|down|watchdog <atrium.toml>\n       atrium submit <atrium.toml> <job.json> | receipt <atrium.toml> <receipt.json> | os-health <atrium.toml>   (atrium-os)\n       atrium fleet <atrium.toml> <verb> ...\n{}", atrium_ctl::fleet::USAGE);
    std::process::exit(64);
}

/// The job door lives in atrium-os (its own crate and licence, nothing linked
/// in here). The front door only hands the verb to the atrium-os binary that
/// sits next to it and passes its exit code through.
fn forward_os(a: &[String]) -> i32 {
    let exe = match std::env::current_exe() {
        Ok(p) => p.with_file_name(if cfg!(windows) { "atrium-os.exe" } else { "atrium-os" }),
        Err(e) => { eprintln!("atrium: cannot locate atrium-os: {e}"); return 69; }
    };
    let verb = if a[1] == "os-health" { "health" } else { a[1].as_str() };
    match std::process::Command::new(&exe).arg(verb).args(&a[2..]).status() {
        Ok(s) => s.code().unwrap_or(70),
        Err(e) => { eprintln!("atrium: {} did not start: {e}", exe.display()); 69 }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 { usage(); }
    // Before Config::load: the OS verbs read only the [os] table of the file they are given.
    if matches!(a[1].as_str(), "submit" | "receipt" | "os-health") { std::process::exit(forward_os(&a)); }
    let cfg = match Config::load(Path::new(&a[2])) { Ok(c) => c, Err(e) => { eprintln!("atrium: {e}"); std::process::exit(65); } };
    let code = match a[1].as_str() {
        "up" => up(cfg),
        "status" => status(&cfg),
        "verify" => verify(cfg),
        "check" => check(&cfg),
        "repair-note" => {
            let (Some(file), why) = (a.get(3), a[4.min(a.len())..].join(" ")) else { usage() };
            let mut sup = match Supervisor::open(cfg) { Ok(s) => s, Err(e) => { eprintln!("atrium: {e}"); std::process::exit(75); } };
            match sup.record_repair(Path::new(file), if why.is_empty() { "no reason given" } else { &why }) {
                Ok(h) => { println!("atrium: repair recorded at seq {}; quarantine sha256 {h}", sup.status().chain_seq - 1); 0 }
                Err(e) => { eprintln!("atrium: {e}"); 70 }
            }
        }
        "down" => down(&cfg),
        // One pass, run every minute by its own scheduled task (see fleet::watchdog_decide).
        "watchdog" => atrium_ctl::fleet::Fleet::new(cfg).watchdog(),
        "fleet" => {
            // fleet `down` re-invokes this binary with the same config.
            std::env::set_var("ATRIUM_CONFIG", &a[2]);
            let f = atrium_ctl::fleet::Fleet::new(cfg);
            if a.get(3).map(|s| s == "bot").unwrap_or(false) { f.bot() } else {
                let (ok, text) = f.exec(&a[3..]);
                println!("{text}");
                if ok { 0 } else { 1 }
            }
        }
        _ => usage(),
    };
    std::process::exit(code);
}

fn stop_file(state: &Path) -> std::path::PathBuf { state.join("stop") }

enum Hold { Back, Stop }

/// The drive is writable again: the state dir exists, the chain file is there,
/// and a probe file can be written and synced.
fn drive_back(state: &Path) -> bool {
    if fs::metadata(state.join("receipts.jsonl")).is_err() { return false; }
    let probe = state.join(".drive-probe");
    let ok = fs::OpenOptions::new().create(true).truncate(true).write(true).open(&probe)
        .and_then(|mut f| { f.write_all(b"probe")?; f.sync_all() }).is_ok();
    let _ = fs::remove_file(&probe);
    ok
}

/// Wait without writing to the chain until the drive answers again (or `down` is asked).
fn wait_for_drive(state: &Path) -> Hold {
    let t0 = Instant::now();
    let mut next_note = Duration::from_secs(60);
    loop {
        std::thread::sleep(DRIVE_PROBE);
        if stop_file(state).exists() { let _ = fs::remove_file(stop_file(state)); return Hold::Stop; }
        if drive_back(state) { return Hold::Back; }
        if t0.elapsed() >= next_note {
            eprintln!("[{}] still waiting for the drive under {} ({}s)", now_unix(), state.display(), t0.elapsed().as_secs());
            next_note += Duration::from_secs(60);
        }
    }
}

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
    let mut sup = match Supervisor::open(cfg.clone()) { Ok(s) => s, Err(e) => { eprintln!("atrium: {e}"); return 70; } };
    sup.start_selfcheck();
    slog(&state, &format!("up: pid {} chain seq {} head {}", std::process::id(), sup.status().chain_seq, &sup.status().chain_head[..12]));
    let mut last_all_up: Option<bool> = None;
    loop {
        let t0 = Instant::now();
        let step = sup.tick().and_then(|_| sup.service_requests());
        match step {
            Ok(()) => {
                let now_up = sup.status().all_up();
                if last_all_up != Some(now_up) {
                    let down: Vec<&str> = sup.status().rooms.iter().filter(|(_, r)| r.health != Health::Up).map(|(n, _)| n.as_str()).collect();
                    slog(&state, &if now_up { "all rooms up".to_string() } else { format!("not all up: {}", down.join(", ")) });
                    last_all_up = Some(now_up);
                }
            }
            Err(e) if is_device_lost(&e) => {
                // The drive under the chain went away. Never write through it:
                // release the chain, wait, reopen (which re-verifies), record the gap.
                let (from_seq, lost_at, why) = (sup.status().chain_seq, now_unix(), e.to_string());
                eprintln!("[{lost_at}] drive lost at seq {from_seq} ({why}); holding, no writes until it is back");
                sup.release();
                if let Hold::Stop = wait_for_drive(&state) { eprintln!("atrium: down requested while the drive was gone"); return 0; }
                sup = match Supervisor::open(cfg.clone()) {
                    Ok(s) => s,
                    Err(e) => { slog(&state, &format!("drive back but the chain will not reopen, stopping (chain must not drift): {e}")); return 70; }
                };
                let lost = now_unix().saturating_sub(lost_at);
                if let Err(e) = sup.record_gap(from_seq, lost, &why) {
                    slog(&state, &format!("gap receipt failed, stopping (chain must not drift): {e}"));
                    let _ = sup.shutdown_fatal(&format!("gap receipt failed: {e}"));
                    return 74;
                }
                sup.start_selfcheck();
                slog(&state, &format!("drive back after {lost}s; chain reopened and verified at seq {}, gap recorded, resuming", sup.status().chain_seq));
                last_all_up = None;
                continue;
            }
            Err(e) => { slog(&state, &format!("tick failed, stopping (chain must not drift): {e}")); let _ = sup.shutdown_fatal(&format!("tick failed: {e}")); return 74; }
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
    if let (false, Some(why)) = (live, &s.fatal) { println!("  last stop was FATAL: {why}"); }
    for (n, r) in &s.rooms {
        let h = match r.health { Health::Up => "up", Health::Down => "DOWN", Health::Blocked => "blocked" };
        println!("  {n:<16} {h:<8} pid {:<7} restarts {:<3} {}", r.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()), r.restarts, r.note);
    }
    if !live { 3 } else if s.all_up() { 0 } else { 2 }
}

fn verify(cfg: Config) -> i32 {
    // One writer per chain: with a live supervisor, verify never appends
    // itself. It queues a request and the supervisor runs the steps and writes
    // every receipt, so rooms stay up. With no supervisor, it runs here.
    if let Ok(s) = Status::load(&cfg.state) {
        if s.live(Duration::from_secs(10)) { return verify_via_supervisor(&cfg, s.supervisor_pid); }
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

fn verify_via_supervisor(cfg: &Config, pid: u32) -> i32 {
    let dir = cfg.state.join("requests");
    if let Err(e) = fs::create_dir_all(&dir) { eprintln!("atrium: {e}"); return 74; }
    let id = format!("verify-{}-{}", atrium_ctl::now_unix(), std::process::id());
    let tmp = dir.join(format!("{id}.req.tmp"));
    if let Err(e) = fs::write(&tmp, b"verify").and_then(|_| fs::rename(&tmp, dir.join(format!("{id}.req")))) {
        eprintln!("atrium: queue {id}: {e}");
        return 74;
    }
    println!("atrium: queued {id} to live supervisor pid {pid}; rooms stay up");
    let budget: u64 = cfg.verify.iter().map(|s| s.timeout_secs).sum::<u64>() + 600;
    let done = dir.join(format!("{id}.done"));
    let deadline = Instant::now() + Duration::from_secs(budget);
    while Instant::now() < deadline {
        if let Ok(text) = fs::read_to_string(&done) {
            let _ = fs::remove_file(&done);
            let mut code = 1;
            for l in text.lines() {
                match l.strip_prefix("exit ") { Some(c) => code = c.trim().parse().unwrap_or(1), None => println!("{l}") }
            }
            return code;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    eprintln!("atrium: no answer for {id} in {budget}s; it may still be running (see {})", dir.display());
    1
}

fn check(cfg: &Config) -> i32 {
    let kid = atrium_ctl::own_kid(&cfg.state);
    let mut fail = 0;
    for (name, ok, detail) in atrium_ctl::chain_reports(cfg, kid.as_deref()) {
        println!("{} {name}: {detail}", if ok { "PASS" } else { "FAIL" });
        if !ok { fail += 1; }
    }
    if fail == 0 { 0 } else { 1 }
}

fn down(cfg: &Config) -> i32 {
    let s = match Status::load(&cfg.state) { Ok(s) => s, Err(_) => { println!("atrium: no supervisor"); return 0; } };
    if !s.live(Duration::from_secs(10)) { println!("atrium: supervisor not live (last pid {})", s.supervisor_pid); return 0; }
    if let Err(e) = fs::write(stop_file(&cfg.state), b"stop") { eprintln!("atrium: {e}"); return 74; }
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        if !stop_file(&cfg.state).exists() {
            // The stop is acknowledged before the process ends. Wait for it to
            // exit, so the writer lock is free for whatever runs next (verify, up).
            let gone = Instant::now() + Duration::from_secs(30);
            while atrium_ctl::pid_alive(s.supervisor_pid) && Instant::now() < gone { std::thread::sleep(Duration::from_millis(100)); }
            if atrium_ctl::pid_alive(s.supervisor_pid) {
                eprintln!("atrium: supervisor pid {} acknowledged the stop but is still running after 30s", s.supervisor_pid);
                return 1;
            }
            println!("atrium: stopped");
            return 0;
        }
    }
    eprintln!("atrium: supervisor did not acknowledge in 15s");
    1
}
