//! ductei-route: decide | outcome
//!   ductei-route decide  --task FILE.json [--approve commit,push] [--state DIR]
//!   ductei-route outcome --task FILE.json --tier t1_claude --ok true|false [--state DIR]
//! Exit codes for decide: 0 allow, 2 needs approval, 3 deny, 1 error.

use ductei_mcp::{ReceiptBody, ReceiptLog, SignCfg};
use ductei_router::*;
use std::path::PathBuf;

const DEFAULT_STATE: &str = r"D:\dev\ductei-router-state";

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let state = PathBuf::from(arg(&args, "--state").unwrap_or_else(|| DEFAULT_STATE.into()));
    let canon = Canon::default();
    // The state dir obeys CANON too.
    if let Verdict::Deny(r) = canon.check(&Task { id: "state".into(), intent: "state".into(), kind: Kind::Chat, criticality: 0, private: true, effects: vec![Effect::Write(state.clone())] }, &[]) {
        return Err(format!("state dir refused: {r}"));
    }
    std::fs::create_dir_all(&state).map_err(|e| e.to_string())?;
    let task_path = arg(&args, "--task").ok_or("missing --task FILE.json")?;
    let task: Task = serde_json::from_str(&std::fs::read_to_string(&task_path).map_err(|e| format!("{task_path}: {e}"))?).map_err(|e| format!("bad task json: {e}"))?;
    let outcomes = state.join("outcomes.jsonl");

    match cmd {
        "decide" => {
            let approvals: Vec<String> = arg(&args, "--approve").map(|s| s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()).unwrap_or_default();
            let verdict = canon.check(&task, &approvals);
            let (tier, reason, escalated) = route(&task, &Stats::load(&outcomes).map_err(|e| e.to_string())?);
            let d = Decision { task_id: task.id.clone(), tier, reason, escalated, verdict };
            let mut log = ReceiptLog::open(&state, &SignCfg::default())?;
            let body = ReceiptBody::new(task.id.clone(), format!("router:{}", serde_json::to_value(tier).unwrap().as_str().unwrap_or("?")), d.verdict.label(), 0, 0, sha256_json(&task), sha256_json(&d));
            let receipt = log.record(body).map_err(|e| e.to_string())?;
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "decision": d, "receipt": receipt.hash })).unwrap());
            Ok(match d.verdict { Verdict::Allow => 0, Verdict::NeedsApproval(_) => 2, Verdict::Deny(_) => 3 })
        }
        "outcome" => {
            let tier: Tier = serde_json::from_value(serde_json::Value::String(arg(&args, "--tier").ok_or("missing --tier")?)).map_err(|e| format!("bad tier: {e}"))?;
            let ok = arg(&args, "--ok").ok_or("missing --ok")? == "true";
            append_outcome(&outcomes, &Outcome { task_id: task.id, kind: task.kind, tier, ok }).map_err(|e| e.to_string())?;
            println!("recorded");
            Ok(0)
        }
        _ => Err("usage: ductei-route decide|outcome --task FILE.json [...]".into()),
    }
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => { eprintln!("ductei-route: {e}"); std::process::exit(1) }
    }
}
