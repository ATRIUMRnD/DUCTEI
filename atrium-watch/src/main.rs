// Copyright (C) 2026 xingxerx
// Licensed under the Apache License 2.0. See the LICENSE file in the repository root.

use atrium_watch::{Config, Watcher};
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(path) = args.get(1) else { eprintln!("usage: atrium-watch <watch.toml> [--once]"); std::process::exit(2) };
    let once = args.iter().any(|a| a == "--once");
    let cfg: Config = match std::fs::read_to_string(path).map_err(|e| e.to_string()).and_then(|t| toml::from_str(&t).map_err(|e| e.to_string())) {
        Ok(c) => c,
        Err(e) => { eprintln!("atrium-watch: {path}: {e}"); std::process::exit(2) }
    };
    let mut w = match Watcher::open(cfg) { Ok(w) => w, Err(e) => { eprintln!("atrium-watch: {e}"); std::process::exit(2) } };
    eprintln!("atrium-watch: watching, offset {}", w.state.offset);
    loop {
        let alarms = w.poll();
        let n = alarms.len();
        for a in &alarms { w.raise(a); }
        if once { std::process::exit(if n == 0 { 0 } else { 1 }); }
        std::thread::sleep(Duration::from_millis(w.poll_ms()));
    }
}
