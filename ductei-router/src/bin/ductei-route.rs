//! ductei-route: classify | decide | outcome | serve (MCP stdio server) | verify
//!   ductei-route classify --intent TEXT [--id ID] [--state DIR]
//!   ductei-route decide  --task FILE.json [--approve commit,push] [--state DIR]
//!   ductei-route outcome --task FILE.json --tier t1_claude --ok true|false [--state DIR]
//!   ductei-route serve [--state DIR]
//!   ductei-route verify [--state DIR]          (walk the receipt chain)
//! Exit codes for decide: 0 allow, 2 needs approval, 3 deny, 1 error.
//! State dir: --state, else DUCTEI_ROUTER_STATE, else D:\dev\ductei-router-state.

use ductei_router::*;
use std::path::PathBuf;

const DEFAULT_STATE: &str = r"D:\dev\ductei-router-state";

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

pub fn state_dir(args: &[String]) -> PathBuf {
    PathBuf::from(arg(args, "--state").or_else(|| std::env::var("DUCTEI_ROUTER_STATE").ok()).unwrap_or_else(|| DEFAULT_STATE.into()))
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    if cmd == "--version" || cmd == "-V" { println!("ductei-route {}", env!("CARGO_PKG_VERSION")); return Ok(0); }
    let state = state_dir(&args);
    // The state dir obeys CANON too (defaults only: canon.toml lives inside it).
    if let Verdict::Deny(r) = Canon::default().check(&Task { id: "state".into(), intent: "state".into(), kind: Kind::Chat, criticality: 0, private: true, effects: vec![Effect::Write(state.clone())] }, &[]) {
        return Err(format!("state dir refused: {r}"));
    }
    std::fs::create_dir_all(&state).map_err(|e| e.to_string())?;
    match cmd {
        "classify" => {
            let intent = arg(&args, "--intent").ok_or("missing --intent TEXT")?;
            let id = arg(&args, "--id").unwrap_or_else(|| format!("c{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)));
            let c = brain::classify(&brain::Ollama::default(), &id, &intent);
            println!("{}", serde_json::to_string_pretty(&c).unwrap());
            Ok(if c.fallback.is_some() { 2 } else { 0 })
        }
        "serve" => { mcp::serve(&state).map_err(|e| e.to_string())?; Ok(0) }
        "verify" => {
            let sign = load_sign(&state)?;
            let log = ductei_mcp::ReceiptLog::open(&state, &sign)?;
            println!("{}", serde_json::json!({ "state": state, "receipts": log.seq, "head": log.head, "scheme": sign.scheme.as_str() }));
            Ok(0)
        }
        "decide" | "outcome" => {
            let task_path = arg(&args, "--task").ok_or("missing --task FILE.json")?;
            let task: Task = serde_json::from_str(&std::fs::read_to_string(&task_path).map_err(|e| format!("{task_path}: {e}"))?).map_err(|e| format!("bad task json: {e}"))?;
            if cmd == "decide" {
                let approvals: Vec<String> = arg(&args, "--approve").map(|s| s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()).unwrap_or_default();
                let d = decide(&state, &task, &approvals)?;
                println!("{}", serde_json::to_string_pretty(&d).unwrap());
                Ok(exit_code(&d.decision.verdict))
            } else {
                let tier: Tier = serde_json::from_value(serde_json::Value::String(arg(&args, "--tier").ok_or("missing --tier")?)).map_err(|e| format!("bad tier: {e}"))?;
                let ok = arg(&args, "--ok").ok_or("missing --ok")? == "true";
                append_outcome(&state.join("outcomes.jsonl"), &Outcome { task_id: task.id, kind: task.kind, tier, ok }).map_err(|e| e.to_string())?;
                println!("recorded");
                Ok(0)
            }
        }
        _ => Err("usage: ductei-route classify|decide|outcome|serve|verify [--state DIR] ...".into()),
    }
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => { eprintln!("ductei-route: {e}"); std::process::exit(1) }
    }
}
